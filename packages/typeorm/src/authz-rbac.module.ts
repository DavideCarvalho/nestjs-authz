import { createRequire } from 'node:module';
import {
  CONTEXT_ACCESSOR,
  PERMISSION_PROVIDER,
  type PermissionProvider,
  ROLE_PROVIDER,
  type RoleProvider,
} from '@dudousxd/nestjs-authz';
import type { UserRef } from '@dudousxd/nestjs-authz/store-kit';
import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnModuleInit,
  Optional,
  type Provider,
  type Type,
} from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import {
  type AuthzTenancyOption,
  type RbacTenant,
  type TenantContextAccessor,
  type TenantResolver,
  acrossScopes,
  inAnyScope,
  rbacTenant,
} from './tenancy.js';
import { TypeOrmAuthzStore } from './typeorm-authz.store.js';
import type { AuthzStoreOptions } from './types.js';

/** Injection token holding the {@link TypeOrmAuthzStore} the RBAC module manages. */
export const AUTHZ_RBAC_STORE = Symbol.for('@dudousxd/nestjs-authz-typeorm:store');
/** Injection token holding the resolved {@link AuthzRbacModuleOptions}. */
export const AUTHZ_RBAC_OPTIONS = Symbol.for('@dudousxd/nestjs-authz-typeorm:options');

/**
 * Map the Gate's current user (whatever the app's auth layer produced) to a
 * {@link UserRef} the store can key on. Defaults to reading `{ type, id }` / `{ id }`.
 */
export type UserRefMapper = (user: unknown) => UserRef | undefined;

export interface AuthzRbacModuleBaseOptions {
  /**
   * Run `ensureAuthzSchema` on bootstrap (default `true`, non-destructive). Set `false`
   * to manage the schema via your ORM's migrations (`createAuthzTables` helper).
   */
  autoCreateSchema?: boolean;
  /**
   * Derive a {@link UserRef} from the Gate's current user. Defaults to
   * {@link defaultUserRefMapper} (`{ type, id }` or `{ id }`).
   */
  userRefFrom?: UserRefMapper;
  /**
   * Tenancy, from `@dudousxd/nestjs-context`. `'inherit'` (default) follows `ContextModule`'s
   * `tenancy.enabled`; with it on, checks are scoped to the context tenant. The object form adds
   * `kinds` and `roles` (map the caller's `tenant.role` to authz roles in that tenant).
   */
  tenancy?: AuthzTenancyOption;
  /**
   * Explicit tenant for a check, from the user being checked. Wins over the context: return a
   * tenant id, `null` for the global scope, or `undefined` to fall back to the context.
   */
  tenant?: TenantResolver;
}

/**
 * Where the store comes from: build it yourself (`store`), or name a TypeORM connection
 * registered with NestJS's `@nestjs/typeorm` (`connectionName`, `'default'` for the default one) and
 * the module builds the store from `getDataSourceToken(connectionName)`, with `storeOptions`.
 */
export type AuthzRbacModuleOptions = AuthzRbacModuleBaseOptions &
  (
    | {
        /** The RBAC store, built with the app-provided TypeORM connection. */
        store: TypeOrmAuthzStore;
        connectionName?: never;
        storeOptions?: never;
      }
    | {
        /** The `@nestjs/typeorm` connection to build the store from (`'default'` for the default one). */
        connectionName: string;
        /** Options for the store built from `connectionName` (table names, schema). */
        storeOptions?: AuthzStoreOptions;
        store?: never;
      }
  );

/** {@link AuthzRbacModuleOptions} once the store is resolved — what the providers read. */
type ResolvedRbacOptions = AuthzRbacModuleBaseOptions & { store: TypeOrmAuthzStore };

export type AuthzRbacModuleAsyncOptions =
  | {
      imports?: unknown[];
      inject?: unknown[];
      useFactory: (...args: unknown[]) => Promise<AuthzRbacModuleOptions> | AuthzRbacModuleOptions;
      connectionName?: never;
      storeOptions?: never;
    }
  | {
      /** Build the store from this `@nestjs/typeorm` connection; the factory returns the other options. */
      connectionName: string;
      storeOptions?: AuthzStoreOptions;
      imports?: unknown[];
      inject?: unknown[];
      useFactory?: (
        ...args: unknown[]
      ) => Promise<AuthzRbacModuleBaseOptions> | AuthzRbacModuleBaseOptions;
    };

const requirePeer = createRequire(import.meta.url);

/**
 * The injection token `@nestjs/typeorm` registers the connection `name` under, from its own
 * `getDataSourceToken()`. An optional peer, loaded only for `connectionName`.
 */
function connectionToken(name: string): unknown {
  let official: { getDataSourceToken(name?: string): unknown };
  try {
    official = requirePeer('@nestjs/typeorm');
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    const message = String((error as { message?: unknown }).message ?? '');
    if (
      (code === 'MODULE_NOT_FOUND' || code === 'ERR_MODULE_NOT_FOUND') &&
      message.includes("'@nestjs/typeorm'")
    ) {
      throw new Error(
        'AuthzRbacModule: connectionName needs @nestjs/typeorm, which is not installed. ' +
          'Install it, or build the store yourself and pass `store`.',
      );
    }
    throw error;
  }
  return official.getDataSourceToken(name);
}

/** Default mapping: accept a `{ type, id }` ref, a `{ id }` object, or a bare id. */
export function defaultUserRefMapper(user: unknown): UserRef | undefined {
  if (user == null) return undefined;
  if (typeof user === 'string' || typeof user === 'number') return user;
  const u = user as { type?: unknown; id?: unknown };
  if (u.id == null) return undefined;
  const id = u.id as string | number;
  return typeof u.type === 'string' ? { type: u.type, id } : { id };
}

/**
 * The RBAC {@link PermissionProvider} the Gate consults (via the shared
 * {@link PERMISSION_PROVIDER} token). Grants a named ability when the current user holds
 * the matching persisted permission — the Laravel/spatie `Gate::before` grant.
 */
@Injectable()
class RbacPermissionProvider implements PermissionProvider {
  // `getPermissions` lists every grant `hasPermission` can find, for any resource.
  readonly exhaustivePermissions = true;

  private readonly contextCache = {
    resolved: false,
    value: undefined as TenantContextAccessor | undefined,
  };

  constructor(
    @Inject(AUTHZ_RBAC_OPTIONS) private readonly options: ResolvedRbacOptions,
    @Optional() @Inject(CONTEXT_ACCESSOR) private readonly context?: TenantContextAccessor,
    @Optional() private readonly moduleRef?: ModuleRef,
  ) {}

  private tenant(user: unknown, ref: UserRef): RbacTenant {
    return rbacTenant(
      this.options,
      user,
      ref,
      this.context,
      this.moduleRef,
      this.contextCache,
      true,
    );
  }

  /** The permissions `tenancy.roles` grants through the caller's role in the tenant. */
  private async tenantRolePermissions(roles: string[]): Promise<string[]> {
    if (roles.length === 0) return [];
    return Object.values(await this.options.store.getRolePermissions(roles)).flat();
  }

  // The core `PermissionProvider` interface passes an optional `resource` (3rd
  // arg); it is intentionally ignored here. RBAC grants are model-less,
  // named-ability grants (the Laravel/spatie `Gate::before` grant), so the
  // verdict never depends on a specific resource instance. Permissions are scoped
  // by the current tenant (from nestjs-context, when present) — a tenant-scoped
  // role only grants within its tenant; direct user grants always apply.
  async hasPermission(user: unknown, permission: string): Promise<boolean | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = this.tenant(user, ref);
    if (
      await inAnyScope(tenant, (scope) =>
        this.options.store.userHasPermission(ref, permission, scope),
      )
    ) {
      return true;
    }
    return (await this.tenantRolePermissions(tenant.roles)).includes(permission);
  }

  // Expose the user's full granted permission set so the core can apply
  // Laravel/spatie-style wildcard matching (a granted `posts.*` satisfies a check
  // for `posts.update`, `*` satisfies anything). The matching itself lives in core,
  // so every adapter that lists grants gets wildcard semantics for free.
  async getPermissions(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = this.tenant(user, ref);
    const own = await acrossScopes(tenant, (scope) =>
      this.options.store.getPermissionsForUser(ref, scope),
    );
    if (tenant.roles.length === 0) return own;
    return [...new Set([...own, ...(await this.tenantRolePermissions(tenant.roles))])];
  }
}

/**
 * The RBAC {@link RoleProvider} the Gate consults (via the shared {@link ROLE_PROVIDER}
 * token) for coarse role-checks (`gate.hasRole('teacher')`, `@Roles('admin')`). Returns
 * the role names the current user holds in the persisted store. Core unions these with
 * any roles read off the user object by the default `RoleResolver`.
 */
@Injectable()
class RbacRoleProvider implements RoleProvider {
  private readonly contextCache = {
    resolved: false,
    value: undefined as TenantContextAccessor | undefined,
  };

  constructor(
    @Inject(AUTHZ_RBAC_OPTIONS) private readonly options: ResolvedRbacOptions,
    @Optional() @Inject(CONTEXT_ACCESSOR) private readonly context?: TenantContextAccessor,
    @Optional() private readonly moduleRef?: ModuleRef,
  ) {}

  async getRoles(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    // Scope roles by the current tenant: a tenant-scoped role only counts within its
    // tenant; global roles always count. `tenancy.roles` adds the caller's tenant roles.
    const tenant = rbacTenant(
      this.options,
      user,
      ref,
      this.context,
      this.moduleRef,
      this.contextCache,
      true,
    );
    const own = await acrossScopes(tenant, (scope) =>
      this.options.store.getRolesForUser(ref, scope),
    );
    return tenant.roles.length === 0 ? own : [...new Set([...own, ...tenant.roles])];
  }

  /**
   * Where the user's roles and permissions come from, for the core's dev tools
   * (`authz_explain_check`): the scope the lookups ran in, store vs `tenancy.roles` roles,
   * each role's permissions, and every permission granted in that scope.
   */
  async describeRbac(user: unknown): Promise<
    | {
        tenantId: string | null;
        tenantChain: string[];
        roles: { store: string[]; tenant: string[] };
        rolePermissions: Record<string, string[]>;
        permissions: string[];
      }
    | undefined
  > {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = rbacTenant(
      this.options,
      user,
      ref,
      this.context,
      this.moduleRef,
      this.contextCache,
      true,
    );
    const [own, permissions] = await Promise.all([
      acrossScopes(tenant, (scope) => this.options.store.getRolesForUser(ref, scope)),
      acrossScopes(tenant, (scope) => this.options.store.getPermissionsForUser(ref, scope)),
    ]);
    const roles = [...new Set([...own, ...tenant.roles])];
    const rolePermissions =
      roles.length === 0 ? {} : await this.options.store.getRolePermissions(roles);
    const fromTenantRoles = tenant.roles.flatMap((role) => rolePermissions[role] ?? []);
    return {
      tenantId: tenant.scope.tenantId ?? null,
      tenantChain: tenant.scopes.flatMap((scope) => (scope.tenantId ? [scope.tenantId] : [])),
      roles: { store: own, tenant: tenant.roles },
      rolePermissions,
      permissions: [...new Set([...permissions, ...fromTenantRoles])],
    };
  }
}

/** Runs `ensureAuthzSchema` on bootstrap when `autoCreateSchema` is not disabled. */
@Injectable()
class AuthzRbacBootstrap implements OnModuleInit {
  constructor(
    @Optional() @Inject(AUTHZ_RBAC_OPTIONS) private readonly options?: ResolvedRbacOptions,
  ) {}

  async onModuleInit(): Promise<void> {
    if (!this.options) return;
    if (this.options.autoCreateSchema === false) return;
    await this.options.store.ensureSchema();
  }
}

/**
 * Wires persisted RBAC into the core authz Gate. Either the app builds the
 * {@link TypeOrmAuthzStore} from its `DataSource` (`store`, often in `forRootAsync`'s factory), or names a
 * `@nestjs/typeorm` connection (`connectionName`) and the module builds the store from
 * `getDataSourceToken(connectionName)` — never a hard-coded token. On init it registers the RBAC
 * permission check into the Gate via the {@link PERMISSION_PROVIDER} seam, so
 * `gate.allows('some.permission')` consults persisted permissions, and (by default) ensures the schema exists.
 */
@Module({})
export class AuthzRbacModule {
  static forRoot(options: AuthzRbacModuleOptions): DynamicModule {
    const { connectionName, storeOptions, store, ...base } = options;
    const optionsProvider: Provider =
      connectionName === undefined
        ? { provide: AUTHZ_RBAC_OPTIONS, useValue: { ...base, store } }
        : {
            provide: AUTHZ_RBAC_OPTIONS,
            useFactory: (connection: never): ResolvedRbacOptions => ({
              ...base,
              store: new TypeOrmAuthzStore(connection, storeOptions),
            }),
            inject: [connectionToken(connectionName) as Type<unknown>],
          };
    return {
      module: AuthzRbacModule,
      global: true,
      providers: [optionsProvider, ...AuthzRbacModule.commonProviders()],
      exports: [AUTHZ_RBAC_STORE, PERMISSION_PROVIDER, ROLE_PROVIDER],
    };
  }

  static forRootAsync(options: AuthzRbacModuleAsyncOptions): DynamicModule {
    const inject = (options.inject ?? []) as Array<Type<unknown>>;
    let optionsProvider: Provider;
    if (options.connectionName === undefined) {
      const { useFactory } = options;
      optionsProvider = {
        provide: AUTHZ_RBAC_OPTIONS,
        useFactory: async (...args: unknown[]): Promise<ResolvedRbacOptions> => {
          const resolved = await useFactory(...args);
          if (resolved.connectionName !== undefined) {
            throw new Error(
              'AuthzRbacModule.forRootAsync: pass connectionName next to useFactory, not in the options it returns.',
            );
          }
          const { store, connectionName: _c, storeOptions: _s, ...base } = resolved;
          return { ...base, store };
        },
        inject,
      };
    } else {
      const { useFactory, storeOptions } = options;
      optionsProvider = {
        provide: AUTHZ_RBAC_OPTIONS,
        useFactory: async (
          connection: never,
          ...args: unknown[]
        ): Promise<ResolvedRbacOptions> => ({
          ...((await useFactory?.(...args)) ?? {}),
          store: new TypeOrmAuthzStore(connection, storeOptions),
        }),
        inject: [connectionToken(options.connectionName) as Type<unknown>, ...inject],
      };
    }
    return {
      module: AuthzRbacModule,
      global: true,
      imports: (options.imports ?? []) as DynamicModule[],
      providers: [optionsProvider, ...AuthzRbacModule.commonProviders()],
      exports: [AUTHZ_RBAC_STORE, PERMISSION_PROVIDER, ROLE_PROVIDER],
    };
  }

  private static commonProviders(): Provider[] {
    return [
      RbacPermissionProvider,
      { provide: PERMISSION_PROVIDER, useExisting: RbacPermissionProvider },
      RbacRoleProvider,
      { provide: ROLE_PROVIDER, useExisting: RbacRoleProvider },
      {
        provide: AUTHZ_RBAC_STORE,
        useFactory: (opts: ResolvedRbacOptions) => opts.store,
        inject: [AUTHZ_RBAC_OPTIONS],
      },
      AuthzRbacBootstrap,
    ];
  }
}
