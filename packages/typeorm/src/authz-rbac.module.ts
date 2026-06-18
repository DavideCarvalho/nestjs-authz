import {
  CONTEXT_ACCESSOR,
  PERMISSION_PROVIDER,
  type PermissionProvider,
  ROLE_PROVIDER,
  type RoleProvider,
} from '@dudousxd/nestjs-authz';
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
import type { TypeOrmAuthzStore } from './typeorm-authz.store.js';
import type { UserRef } from './types.js';

/** Injection token holding the {@link TypeOrmAuthzStore} the RBAC module manages. */
export const AUTHZ_RBAC_STORE = Symbol.for('@dudousxd/nestjs-authz-typeorm:store');
/** Injection token holding the resolved {@link AuthzRbacModuleOptions}. */
export const AUTHZ_RBAC_OPTIONS = Symbol.for('@dudousxd/nestjs-authz-typeorm:options');

/**
 * Map the Gate's current user (whatever the app's auth layer produced) to a
 * {@link UserRef} the store can key on. Defaults to reading `{ type, id }` / `{ id }`.
 */
export type UserRefMapper = (user: unknown) => UserRef | undefined;

export interface AuthzRbacModuleOptions {
  /** The TypeORM RBAC store (built with the app-provided DataSource). */
  store: TypeOrmAuthzStore;
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
}

export interface AuthzRbacModuleAsyncOptions {
  imports?: unknown[];
  inject?: unknown[];
  useFactory: (...args: unknown[]) => Promise<AuthzRbacModuleOptions> | AuthzRbacModuleOptions;
}

/**
 * Minimal structural mirror of nestjs-context's accessor — just the `tenantId()`
 * we read. Injected via the shared {@link CONTEXT_ACCESSOR} token with `@Optional()`,
 * so RBAC stays decoupled from nestjs-context (works with or without it).
 */
interface TenantContextAccessor {
  tenantId?: () => string | undefined;
}

/** Read the current tenant from the (optional) context accessor, defensively. */
function tenantScopeFrom(context: TenantContextAccessor | undefined): { tenantId?: string } {
  if (!context || typeof context.tenantId !== 'function') return {};
  let tenantId: string | undefined;
  try {
    tenantId = context.tenantId();
  } catch {
    tenantId = undefined;
  }
  return tenantId == null ? {} : { tenantId };
}

/**
 * Locate the context accessor for tenant scoping. Prefers a value injected into
 * this module; falls back to a non-strict {@link ModuleRef} lookup so an accessor
 * provided by ANY module (the app root, a global ContextModule) is still found —
 * the RBAC module is global and its providers don't import the app's modules, so a
 * plain `@Inject` would miss a root-provided accessor. Mirrors the Gate's seam.
 */
function resolveTenantContext(
  injected: TenantContextAccessor | undefined,
  moduleRef: ModuleRef | undefined,
  cache: { resolved: boolean; value: TenantContextAccessor | undefined },
): TenantContextAccessor | undefined {
  if (injected) return injected;
  if (cache.resolved) return cache.value;
  cache.resolved = true;
  if (moduleRef) {
    try {
      cache.value = moduleRef.get<TenantContextAccessor>(CONTEXT_ACCESSOR, { strict: false });
    } catch {
      cache.value = undefined;
    }
  }
  return cache.value;
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
  private readonly contextCache = {
    resolved: false,
    value: undefined as TenantContextAccessor | undefined,
  };

  constructor(
    @Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions,
    @Optional() @Inject(CONTEXT_ACCESSOR) private readonly context?: TenantContextAccessor,
    @Optional() private readonly moduleRef?: ModuleRef,
  ) {}

  private scope(): { tenantId?: string } {
    return tenantScopeFrom(resolveTenantContext(this.context, this.moduleRef, this.contextCache));
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
    return this.options.store.userHasPermission(ref, permission, this.scope());
  }

  // Expose the user's full granted permission set so the core can apply
  // Laravel/spatie-style wildcard matching (a granted `posts.*` satisfies a check
  // for `posts.update`, `*` satisfies anything). The matching itself lives in core,
  // so every adapter that lists grants gets wildcard semantics for free.
  async getPermissions(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    return this.options.store.getPermissionsForUser(ref, this.scope());
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
    @Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions,
    @Optional() @Inject(CONTEXT_ACCESSOR) private readonly context?: TenantContextAccessor,
    @Optional() private readonly moduleRef?: ModuleRef,
  ) {}

  async getRoles(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    // Scope roles by the current tenant (when nestjs-context is present): a
    // tenant-scoped role only counts within its tenant; global roles always count.
    const scope = tenantScopeFrom(
      resolveTenantContext(this.context, this.moduleRef, this.contextCache),
    );
    return this.options.store.getRolesForUser(ref, scope);
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
 * Wires persisted RBAC into the core authz Gate. The app provides the `DataSource`
 * (via `inject`/`useFactory`) and constructs the {@link TypeOrmAuthzStore} — this module
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
