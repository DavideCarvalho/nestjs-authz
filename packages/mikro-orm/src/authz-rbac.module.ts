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
import type { MikroOrmAuthzStore } from './mikro-orm-authz.store.js';
import {
  type AuthzTenancyOption,
  type RbacTenant,
  type TenantContextAccessor,
  type TenantContextCache,
  type TenantResolver,
  rbacTenant,
} from './tenancy.js';

/** Injection token holding the {@link MikroOrmAuthzStore} the RBAC module manages. */
export const AUTHZ_RBAC_STORE = Symbol.for('@dudousxd/nestjs-authz-mikro-orm:store');
/** Injection token holding the resolved {@link AuthzRbacModuleOptions}. */
export const AUTHZ_RBAC_OPTIONS = Symbol.for('@dudousxd/nestjs-authz-mikro-orm:options');

/**
 * Map the Gate's current user (whatever the app's auth layer produced) to a
 * {@link UserRef} the store can key on. Defaults to reading `{ type, id }` / `{ id }`.
 */
export type UserRefMapper = (user: unknown) => UserRef | undefined;

export interface AuthzRbacModuleOptions {
  /** The MikroORM RBAC store (built with the app-provided EntityManager). */
  store: MikroOrmAuthzStore;
  /**
   * Run `ensureAuthzSchema` on bootstrap (default `true`, non-destructive). Set `false`
   * to manage the schema via MikroORM migrations (`authzSchemaSql` helper).
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

export interface AuthzRbacModuleAsyncOptions {
  imports?: unknown[];
  inject?: unknown[];
  useFactory: (...args: unknown[]) => Promise<AuthzRbacModuleOptions> | AuthzRbacModuleOptions;
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

  private readonly contextCache: TenantContextCache = { resolved: false, value: undefined };

  constructor(
    @Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions,
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
      false,
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
  // verdict never depends on a specific resource instance.
  async hasPermission(user: unknown, permission: string): Promise<boolean | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = this.tenant(user, ref);
    if (await this.options.store.userHasPermission(ref, permission, tenant.scope)) return true;
    return (await this.tenantRolePermissions(tenant.roles)).includes(permission);
  }

  // Expose the user's full granted permission set so the core can apply
  // Laravel/spatie-style wildcard matching (a granted `posts.*` satisfies a check
  // for `posts.update`, `*` satisfies anything) and fetch it once per request.
  async getPermissions(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = this.tenant(user, ref);
    const own = await this.options.store.getPermissionsForUser(ref, tenant.scope);
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
  private readonly contextCache: TenantContextCache = { resolved: false, value: undefined };

  constructor(
    @Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions,
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
      false,
    );
  }

  async getRoles(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = this.tenant(user, ref);
    const own = await this.options.store.getRolesForUser(ref, tenant.scope);
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
        roles: { store: string[]; tenant: string[] };
        rolePermissions: Record<string, string[]>;
        permissions: string[];
      }
    | undefined
  > {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    const tenant = this.tenant(user, ref);
    const [own, permissions] = await Promise.all([
      this.options.store.getRolesForUser(ref, tenant.scope),
      this.options.store.getPermissionsForUser(ref, tenant.scope),
    ]);
    const roles = [...new Set([...own, ...tenant.roles])];
    const rolePermissions =
      roles.length === 0 ? {} : await this.options.store.getRolePermissions(roles);
    const fromTenantRoles = tenant.roles.flatMap((role) => rolePermissions[role] ?? []);
    return {
      tenantId: tenant.scope.tenantId ?? null,
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
    @Optional() @Inject(AUTHZ_RBAC_OPTIONS) private readonly options?: AuthzRbacModuleOptions,
  ) {}

  async onModuleInit(): Promise<void> {
    if (!this.options) return;
    if (this.options.autoCreateSchema === false) return;
    await this.options.store.ensureSchema();
  }
}

/**
 * Wires persisted RBAC into the core authz Gate. The app provides the `EntityManager`
 * (via `inject`/`useFactory`) and constructs the {@link MikroOrmAuthzStore} — this module
 * NEVER hardcodes a connection token. On init it registers the RBAC permission check into
 * the Gate via the {@link PERMISSION_PROVIDER} seam, so `gate.allows('some.permission')`
 * consults persisted permissions, and (by default) ensures the schema exists.
 */
@Module({})
export class AuthzRbacModule {
  static forRoot(options: AuthzRbacModuleOptions): DynamicModule {
    return {
      module: AuthzRbacModule,
      global: true,
      providers: [
        { provide: AUTHZ_RBAC_OPTIONS, useValue: options },
        { provide: AUTHZ_RBAC_STORE, useValue: options.store },
        ...AuthzRbacModule.commonProviders(),
      ],
      exports: [AUTHZ_RBAC_STORE, PERMISSION_PROVIDER, ROLE_PROVIDER],
    };
  }

  static forRootAsync(options: AuthzRbacModuleAsyncOptions): DynamicModule {
    return {
      module: AuthzRbacModule,
      global: true,
      imports: (options.imports ?? []) as DynamicModule[],
      providers: [
        {
          provide: AUTHZ_RBAC_OPTIONS,
          useFactory: options.useFactory,
          inject: (options.inject ?? []) as Array<Type<unknown>>,
        },
        {
          provide: AUTHZ_RBAC_STORE,
          useFactory: (opts: AuthzRbacModuleOptions) => opts.store,
          inject: [AUTHZ_RBAC_OPTIONS],
        },
        ...AuthzRbacModule.commonProviders(),
      ],
      exports: [AUTHZ_RBAC_STORE, PERMISSION_PROVIDER, ROLE_PROVIDER],
    };
  }

  private static commonProviders(): Provider[] {
    return [
      RbacPermissionProvider,
      { provide: PERMISSION_PROVIDER, useExisting: RbacPermissionProvider },
      RbacRoleProvider,
      { provide: ROLE_PROVIDER, useExisting: RbacRoleProvider },
      AuthzRbacBootstrap,
    ];
  }
}
