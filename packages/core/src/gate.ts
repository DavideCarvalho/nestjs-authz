import { ForbiddenException, Inject, Injectable, Optional, type Type } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import type { ContextAccessor, UserRef } from './context-accessor.js';
import { AbilityNotResolvedException, AmbiguousAbilityException } from './errors/exceptions.js';
import type { PermissionProvider } from './permission-provider.js';
import { PolicyRegistry } from './policy-registry.js';
import { AUTHZ_MODULE_OPTIONS, CONTEXT_ACCESSOR, PERMISSION_PROVIDER } from './tokens.js';
import type {
  AuthzModuleOptions,
  GateFn,
  PolicyBeforeHook,
  PolicyInstance,
  Resource,
  SuperAdminHook,
  User,
} from './types.js';

// A sentinel marking "no user resolved" distinct from a legitimately-`undefined`
// user. `forUser(undefined)` explicitly authorizes an anonymous user.
const NO_USER = Symbol('authz:no-user');
type MaybeUser = User | typeof NO_USER;

/**
 * Laravel-style authorization Gate.
 *
 * Resolves an ability against either a registered `@Policy` method (by ability
 * name, matched against the resource's policy) or an ad-hoc gate defined via
 * {@link define}. Applies the global `superAdmin` before-hook and the per-policy
 * `before` hook with short-circuit semantics.
 *
 * The current user comes from the optional {@link ContextAccessor} (nestjs-context)
 * when present, or is supplied explicitly via {@link forUser}.
 */
@Injectable()
export class Gate {
  private readonly gates = new Map<string, GateFn>();
  private readonly superAdmin: SuperAdminHook | undefined;
  private readonly resolveUser: AuthzModuleOptions['resolveUser'];

  constructor(
    private readonly policies: PolicyRegistry,
    @Optional()
    @Inject(AUTHZ_MODULE_OPTIONS)
    options: AuthzModuleOptions | undefined,
    @Optional()
    @Inject(CONTEXT_ACCESSOR)
    private readonly context?: ContextAccessor,
    @Optional()
    private readonly moduleRef?: ModuleRef,
    @Optional()
    @Inject(PERMISSION_PROVIDER)
    private readonly permissionProvider?: PermissionProvider,
  ) {
    this.superAdmin = options?.superAdmin;
    this.resolveUser = options?.resolveUser;
  }

  /**
   * Locate the context accessor. Prefers the value injected into this module;
   * falls back to a non-strict {@link ModuleRef} lookup so an accessor provided
   * by ANY module (e.g. a global ContextModule, or the app root) is still found.
   */
  private resolveContext(): ContextAccessor | undefined {
    if (this.context) return this.context;
    if (!this.moduleRef) return undefined;
    try {
      return this.moduleRef.get<ContextAccessor>(CONTEXT_ACCESSOR, { strict: false });
    } catch {
      return undefined;
    }
  }

  /**
   * Locate the optional {@link PermissionProvider} (the RBAC seam). Prefers the value
   * injected into this module; falls back to a non-strict {@link ModuleRef} lookup so a
   * provider registered by ANY module (e.g. the RBAC adapter's global module) is found.
   */
  private resolvePermissionProvider(): PermissionProvider | undefined {
    if (this.permissionProvider) return this.permissionProvider;
    if (!this.moduleRef) return undefined;
    try {
      return this.moduleRef.get<PermissionProvider>(PERMISSION_PROVIDER, { strict: false });
    } catch {
      return undefined;
    }
  }

  /** Register an ad-hoc, model-less gate resolved by `ability` name. */
  define(ability: string, fn: GateFn): this {
    this.gates.set(ability, fn);
    return this;
  }

  /** True when an ad-hoc gate is registered for `ability`. */
  hasGate(ability: string): boolean {
    return this.gates.has(ability);
  }

  /**
   * Bind an explicit user, bypassing the context accessor. Use when no
   * nestjs-context is wired, or to check a user other than the current one.
   *
   * A nullish user (`forUser(undefined)` / `forUser(null)`) is an explicit
   * anonymous request: it maps to the same deny path as an unauthenticated
   * context (`NO_USER`), so policies/gates are never invoked with `undefined` and
   * never throw. The `resolveUser` hook is NOT applied to `forUser` — the value
   * you pass is used verbatim.
   */
  forUser(user: User): BoundGate {
    return new BoundGate(this, user == null ? NO_USER : user);
  }

  /**
   * Resolve the current user from the context accessor, or `NO_USER`.
   * When a `resolveUser` hook is configured, hydrate the full entity from the
   * context's {@link UserRef}; a hook returning nullish maps to `NO_USER`.
   */
  private async currentUser(): Promise<MaybeUser> {
    const context = this.resolveContext();
    if (!context) return NO_USER;
    const ref = context.userRef();
    if (ref === undefined) return NO_USER;
    if (this.resolveUser) {
      const hydrated = await this.resolveUser(ref as UserRef);
      return hydrated == null ? NO_USER : hydrated;
    }
    return ref;
  }

  // --- public API (operates on the current/context user) ---

  async allows(ability: string, resource?: Resource): Promise<boolean> {
    return this.check(await this.currentUser(), ability, resource);
  }

  async denies(ability: string, resource?: Resource): Promise<boolean> {
    return !(await this.allows(ability, resource));
  }

  async authorize(ability: string, resource?: Resource): Promise<void> {
    if (!(await this.allows(ability, resource))) {
      throw new ForbiddenException(`Unauthorized: ${ability}`);
    }
  }

  // --- internal: used by BoundGate too ---

  /** @internal */
  allowsForUser(user: MaybeUser, ability: string, resource?: Resource): Promise<boolean> {
    return this.check(user, ability, resource);
  }

  private async check(
    maybeUser: MaybeUser,
    ability: string,
    resource?: Resource,
  ): Promise<boolean> {
    const user: User = maybeUser === NO_USER ? undefined : maybeUser;

    // Global super-admin hook first.
    const sa = await this.superAdmin?.(user, ability);
    if (sa === true) return true;
    if (sa === false) return false;

    // RBAC seam (Laravel/spatie `Gate::before` grant): if a PermissionProvider is
    // registered and the (authenticated) user holds the named permission, grant it.
    // Grant-only — a `false`/`undefined` result falls through to normal resolution,
    // so this never *denies* an ability a policy/gate would otherwise allow.
    if (maybeUser !== NO_USER) {
      const provider = this.resolvePermissionProvider();
      if (provider) {
        const granted = await provider.hasPermission(user, ability, resource);
        if (granted === true) return true;
      }
    }

    const policy = this.resolvePolicy(ability, resource);
    if (policy) {
      const method = (policy as Record<string, unknown>)[ability];
      // The `before` hook may only answer abilities the policy actually defines.
      // Gate it on method existence FIRST so a policy with a `before` but no
      // matching method falls through to AbilityNotResolved instead of letting
      // `before` grant/deny an ability the policy never declared.
      if (typeof method === 'function') {
        const before = (policy as PolicyInstance).before as PolicyBeforeHook | undefined;
        if (typeof before === 'function') {
          const result = await before.call(policy, user, ability);
          if (result === true) return true;
          if (result === false) return false;
        }
        // Anonymous users are denied unless a hook granted access above.
        if (maybeUser === NO_USER) return false;
        return Boolean(await (method as (...a: unknown[]) => unknown).call(policy, user, resource));
      }
    }

    // Fall back to an ad-hoc gate.
    const gate = this.gates.get(ability);
    if (gate) {
      if (maybeUser === NO_USER) return false;
      return Boolean(await gate(user, resource));
    }

    throw new AbilityNotResolvedException(ability);
  }

  private resolvePolicy(ability: string, resource?: Resource): PolicyInstance | undefined {
    if (resource === undefined) {
      // Class-level ability with no resource: scan registered policies for the
      // method. If MORE THAN ONE policy defines it, picking by Map-insertion
      // order would be a silent, arbitrary (and likely wrong) choice — throw so
      // the caller disambiguates by passing the resource class explicitly.
      const matches = this.policies
        .all()
        .filter((policy) => typeof (policy as Record<string, unknown>)[ability] === 'function');
      if (matches.length === 0) return undefined;
      if (matches.length > 1) {
        throw new AmbiguousAbilityException(
          ability,
          matches.map((p) => (p as PolicyInstance).constructor?.name ?? 'Policy'),
        );
      }
      return matches[0];
    }
    // Resource may be an instance or a class (for class-level abilities passed as Type).
    if (typeof resource === 'function') {
      return this.policies.forResource(resource as Type<unknown>);
    }
    return this.policies.forInstance(resource);
  }
}

/**
 * A {@link Gate} bound to an explicit user. Returned by {@link Gate.forUser}.
 */
export class BoundGate {
  constructor(
    private readonly gate: Gate,
    private readonly user: MaybeUser,
  ) {}

  allows(ability: string, resource?: Resource): Promise<boolean> {
    return this.gate.allowsForUser(this.user, ability, resource);
  }

  async denies(ability: string, resource?: Resource): Promise<boolean> {
    return !(await this.allows(ability, resource));
  }

  async authorize(ability: string, resource?: Resource): Promise<void> {
    if (!(await this.allows(ability, resource))) {
      throw new ForbiddenException(`Unauthorized: ${ability}`);
    }
  }
}
