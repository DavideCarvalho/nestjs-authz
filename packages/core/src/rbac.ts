import { InjectCapability } from '@dudousxd/nestjs-diagnostics/nestjs';
import { Inject, Injectable, type OnModuleInit, Optional } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import type { ContextAccessor, ContextStore } from './context-accessor.js';
import type { DecisionProvider } from './decision-provider.js';
import { PermissionCache } from './permission-cache.js';
import { permissionSatisfied } from './permission-matcher.js';
import type { PermissionProvider } from './permission-provider.js';
import { type RoleProvider, type RoleResolver, defaultRoleResolver } from './role-provider.js';
import {
  AUTHZ_MODULE_OPTIONS,
  CONTEXT_ACCESSOR,
  DECISION_PROVIDER,
  PERMISSION_PROVIDER,
  ROLE_PROVIDER,
} from './tokens.js';
import type { AuthzModuleOptions, Resource, User } from './types.js';

/**
 * Key of the per-request {@link PermissionCache} on the nestjs-context store. `Symbol.for`
 * so every copy of this module shares it.
 */
const REQUEST_PERMISSION_CACHE = Symbol.for('@dudousxd/nestjs-authz:request-permission-cache');

/** Key under which the per-request `resolveUser` results are stashed on the context store. */
const REQUEST_USERS = Symbol.for('@dudousxd/nestjs-authz:request-users');

/**
 * The slice of `@nestjs/authentication`'s `AuthenticationContext` read here. `scope` is its
 * (TypeScript-private) `AuthenticationScope`: `scope.current` is set inside a call the package
 * handles (its interceptor opened it) and inside `AuthenticationContext.run()`, and `undefined`
 * elsewhere. The package exports no other way to tell "anonymous" from "no scope".
 */
interface AuthenticationContextLike {
  readonly user: unknown;
  readonly scope?: { readonly current?: unknown };
}

/**
 * Roles and permissions of a user, from the persisted RBAC seams (`ROLE_PROVIDER`,
 * `PERMISSION_PROVIDER`, registered by the TypeORM / MikroORM / Prisma / Drizzle adapters)
 * and from the user object itself (`user.roles` / `user.role`); the optional external
 * decision point (`DECISION_PROVIDER`); and the ambient user for `Gate` calls made without
 * one. Shared by `RolePolicy`, `PermissionPolicy`, `AuthzPolicy` and the `Gate`.
 *
 * Within one request (a nestjs-context store), a user's permissions and provider roles
 * are fetched once, however many checks run, in guards and in handlers alike.
 */
@Injectable()
export class AuthzRbac implements OnModuleInit {
  private readonly roleResolver: RoleResolver;
  private readonly resolveUser: AuthzModuleOptions['resolveUser'];
  private readonly lookups = new Map<symbol, { value: unknown }>();
  private authentication: AuthenticationContextLike | undefined;

  constructor(
    @Optional() @Inject(AUTHZ_MODULE_OPTIONS) options: AuthzModuleOptions | undefined,
    @InjectCapability('context', 'accessor') private readonly context?: ContextAccessor,
    @Optional() private readonly moduleRef?: ModuleRef,
    @Optional()
    @Inject(PERMISSION_PROVIDER)
    private readonly permissionProvider?: PermissionProvider,
    @Optional() @Inject(ROLE_PROVIDER) private readonly roleProvider?: RoleProvider,
    @Optional() @Inject(DECISION_PROVIDER) private readonly decisionProvider?: DecisionProvider,
  ) {
    this.roleResolver = options?.resolveRoles ?? defaultRoleResolver;
    this.resolveUser = options?.resolveUser;
  }

  /**
   * Finds `@nestjs/authentication`'s `AuthenticationContext` when that optional peer is
   * installed and its module is imported. The class is the DI token, so the package is
   * loaded only here, and its absence is not an error.
   */
  async onModuleInit(): Promise<void> {
    if (!this.moduleRef || this.authentication) return;
    let token: unknown;
    try {
      const specifier = '@nestjs/authentication';
      token = ((await import(specifier)) as { AuthenticationContext?: unknown })
        .AuthenticationContext;
    } catch {
      return;
    }
    if (typeof token !== 'function') return;
    try {
      this.authentication = this.moduleRef.get(token as new () => AuthenticationContextLike, {
        strict: false,
      });
    } catch {
      this.authentication = undefined;
    }
  }

  /**
   * A provider registered by any module: the injected one, else a non-strict lookup,
   * memoized, so a global RBAC module or a root-level accessor is found too.
   */
  private lookup<T>(token: symbol, injected: T | undefined): T | undefined {
    if (injected) return injected;
    const memo = this.lookups.get(token);
    if (memo) return memo.value as T | undefined;
    let value: T | undefined;
    try {
      value = this.moduleRef?.get<T>(token, { strict: false });
    } catch {
      value = undefined;
    }
    this.lookups.set(token, { value });
    return value;
  }

  /** @internal The nestjs-context accessor, when one is registered. */
  contextAccessor(): ContextAccessor | undefined {
    return this.lookup(CONTEXT_ACCESSOR, this.context);
  }

  /** The persisted permission seam, when an RBAC adapter registered one. */
  permissions(): PermissionProvider | undefined {
    return this.lookup(PERMISSION_PROVIDER, this.permissionProvider);
  }

  /** The persisted role seam, when an RBAC adapter registered one. */
  roles(): RoleProvider | undefined {
    return this.lookup(ROLE_PROVIDER, this.roleProvider);
  }

  /** The external decision point (Cerbos, OPA, …), when one is registered. */
  decisions(): DecisionProvider | undefined {
    return this.lookup(DECISION_PROVIDER, this.decisionProvider);
  }

  /**
   * The user for a `Gate` call made without one:
   *
   * 1. `@nestjs/authentication`'s `AuthenticationContext.user`, when that optional peer is
   *    installed and its scope is active (a call it handles, or `AuthenticationContext.run()`):
   *    its answer is final, so a `null` there is a guest;
   * 2. else, with no authentication scope at all, nestjs-context's user ref, hydrated by
   *    `resolveUser` when configured (once per `type:id` per request);
   * 3. else `null` (a guest).
   */
  async currentUser(): Promise<User> {
    const authenticated = this.authenticatedUser();
    if (authenticated !== undefined) return authenticated;

    const context = this.contextAccessor();
    if (!context) return null;
    const ref = context.userRef();
    if (ref === undefined) return null;
    const resolveUser = this.resolveUser;
    if (!resolveUser) return ref;
    const hydrate = async (): Promise<User> => (await resolveUser(ref)) ?? null;

    const store = this.requestStore();
    if (!store) return hydrate();
    let users = store[REQUEST_USERS] as Map<string, Promise<User>> | undefined;
    if (!(users instanceof Map)) {
      users = new Map();
      store[REQUEST_USERS] = users;
    }
    const key = `${ref.type}:${typeof ref.id}:${ref.id}`;
    const cached = users.get(key);
    if (cached) return cached;
    const pending = hydrate();
    users.set(key, pending);
    pending.catch(() => users.delete(key));
    return pending;
  }

  /**
   * `AuthenticationContext.user` (`null` for an anonymous call) when its scope is active;
   * `undefined` without the package or outside its scope. A version that hides the scope is
   * read as before: a user is an answer, `null` is not.
   */
  private authenticatedUser(): unknown {
    const authentication = this.authentication;
    if (!authentication) return undefined;
    try {
      const scope = authentication.scope;
      if (scope && typeof scope === 'object' && 'current' in scope) {
        return scope.current === undefined ? undefined : (authentication.user ?? null);
      }
      return authentication.user ?? undefined;
    } catch {
      return undefined;
    }
  }

  /** The nestjs-context store for the current request, or `undefined` when there is none. */
  private requestStore(): Record<symbol, unknown> | undefined {
    const context = this.contextAccessor();
    if (!context || typeof context.get !== 'function') return undefined;
    let store: ContextStore | undefined;
    try {
      store = context.get();
    } catch {
      store = undefined;
    }
    return store as Record<symbol, unknown> | undefined;
  }

  /**
   * The per-request {@link PermissionCache} on the nestjs-context store, so every check
   * in one request shares a single `getPermissions` and `getRoles` fetch per user.
   * `undefined` without a store.
   */
  requestCache(): PermissionCache | undefined {
    const store = this.requestStore();
    if (!store) return undefined;
    const existing = store[REQUEST_PERMISSION_CACHE];
    if (existing instanceof PermissionCache) return existing;
    const cache = new PermissionCache();
    store[REQUEST_PERMISSION_CACHE] = cache;
    return cache;
  }

  /**
   * The user's role names: the role resolver's (the user object) and the role provider's,
   * the latter fetched through `cache` (the request's, by default).
   */
  async rolesOf(
    user: User,
    cache: PermissionCache | undefined = this.requestCache(),
  ): Promise<Set<string>> {
    const out = new Set<string>();
    if (user == null) return out;
    const fromResolver = await this.roleResolver(user);
    if (Array.isArray(fromResolver)) {
      for (const r of fromResolver) if (typeof r === 'string') out.add(r);
    }
    const provider = this.roles();
    if (provider) {
      const fromProvider = await (cache ? cache.getRoles(provider, user) : provider.getRoles(user));
      if (Array.isArray(fromProvider)) {
        for (const r of fromProvider) if (typeof r === 'string') out.add(r);
      }
    }
    return out;
  }

  /** True when the user holds any of `roles`. A guest holds none. */
  async hasAnyRole(
    user: User,
    roles: readonly string[],
    cache?: PermissionCache | undefined,
  ): Promise<boolean> {
    if (user == null || roles.length === 0) return false;
    const held = await this.rolesOf(user, cache ?? this.requestCache());
    return roles.some((r) => held.has(r));
  }

  /** True when the user holds every one of `roles`. */
  async hasAllRoles(user: User, roles: readonly string[]): Promise<boolean> {
    if (user == null || roles.length === 0) return false;
    const held = await this.rolesOf(user);
    return roles.every((r) => held.has(r));
  }

  /**
   * True when the permission seam grants `permission` to `user`. With `getPermissions`,
   * wildcard grants apply (`posts.*` satisfies `posts.update`, `*` anything), fetched
   * once per `cache` (the request's, by default). A set the provider marks
   * `exhaustivePermissions` answers on its own; otherwise a miss still asks the
   * exact-match `hasPermission`. A guest, or no seam, is never granted.
   */
  async grants(
    user: User,
    permission: string,
    resource?: Resource,
    cache: PermissionCache | undefined = this.requestCache(),
  ): Promise<boolean> {
    if (user == null) return false;
    const provider = this.permissions();
    if (!provider) return false;
    if (typeof provider.getPermissions === 'function') {
      const satisfied = cache
        ? await cache.satisfies(provider, user, permission)
        : await (async () => {
            const granted = await provider.getPermissions?.(user);
            return granted == null ? undefined : permissionSatisfied(granted, permission);
          })();
      if (satisfied === true) return true;
      if (satisfied === false && provider.exhaustivePermissions === true) return false;
    }
    return (await provider.hasPermission(user, permission, resource)) === true;
  }
}
