import {
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
import { PrismaAuthzStore } from './prisma-authz.store.js';
import { PRISMA_CLIENT, type PrismaAuthzClientLike } from './prisma-client.js';
import type { UserRef } from './types.js';

/** Injection token holding the {@link PrismaAuthzStore} the RBAC module manages. */
export const AUTHZ_RBAC_STORE = Symbol.for('@dudousxd/nestjs-authz-prisma:store');
/** Injection token holding the resolved {@link AuthzRbacModuleOptions}. */
export const AUTHZ_RBAC_OPTIONS = Symbol.for('@dudousxd/nestjs-authz-prisma:options');

/**
 * Map the Gate's current user (whatever the app's auth layer produced) to a
 * {@link UserRef} the store can key on. Defaults to reading `{ type, id }` / `{ id }`.
 */
export type UserRefMapper = (user: unknown) => UserRef | undefined;

export interface AuthzRbacModuleOptions {
  /**
   * The Prisma RBAC store, OR the raw Prisma client. Pass `store` if you already built a
   * {@link PrismaAuthzStore}; pass `client` to let the module build one (a real
   * `PrismaClient` structurally satisfies {@link PrismaAuthzClientLike}).
   */
  store?: PrismaAuthzStore;
  /** The app-owned Prisma client; used to build the store when `store` is omitted. */
  client?: PrismaAuthzClientLike;
  /**
   * Prisma is consumer-managed (schema-first) — there is no auto-create. This flag exists
   * for parity; the store's `ensureSchema` is a no-op regardless. Default `false`.
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

/** Default mapping: accept a `{ type, id }` ref, a `{ id }` object, or a bare id. */
export function defaultUserRefMapper(user: unknown): UserRef | undefined {
  if (user == null) return undefined;
  if (typeof user === 'string' || typeof user === 'number') return user;
  const u = user as { type?: unknown; id?: unknown };
  if (u.id == null) return undefined;
  const id = u.id as string | number;
  return typeof u.type === 'string' ? { type: u.type, id } : { id };
}

/** Resolve a concrete store from the options (building one from `client` when needed). */
function resolveStore(options: AuthzRbacModuleOptions): PrismaAuthzStore {
  if (options.store) return options.store;
  if (options.client) return new PrismaAuthzStore(options.client);
  throw new Error('AuthzRbacModule (prisma): provide either `store` or `client` in the options.');
}

/**
 * The RBAC {@link PermissionProvider} the Gate consults (via the shared
 * {@link PERMISSION_PROVIDER} token). Grants a named ability when the current user holds
 * the matching persisted permission — the Laravel/spatie `Gate::before` grant.
 */
@Injectable()
class RbacPermissionProvider implements PermissionProvider {
  private readonly store: PrismaAuthzStore;
  constructor(@Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions) {
    this.store = resolveStore(options);
  }

  // The core `PermissionProvider` interface passes an optional `resource` (3rd
  // arg); it is intentionally ignored here. RBAC grants are model-less,
  // named-ability grants (the Laravel/spatie `Gate::before` grant), so the
  // verdict never depends on a specific resource instance.
  async hasPermission(user: unknown, permission: string): Promise<boolean | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    return this.store.userHasPermission(ref, permission);
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
  private readonly store: PrismaAuthzStore;
  constructor(@Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions) {
    this.store = resolveStore(options);
  }

  async getRoles(user: unknown): Promise<string[] | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    return this.store.getRolesForUser(ref);
  }
}

/**
 * Runs `ensureSchema` on bootstrap when `autoCreateSchema` is enabled. For Prisma this is
 * a no-op (schema is consumer-managed) — kept for parity with the other adapters.
 */
@Injectable()
class AuthzRbacBootstrap implements OnModuleInit {
  constructor(
    @Optional() @Inject(AUTHZ_RBAC_OPTIONS) private readonly options?: AuthzRbacModuleOptions,
  ) {}

  async onModuleInit(): Promise<void> {
    if (!this.options) return;
    if (this.options.autoCreateSchema !== true) return;
    await resolveStore(this.options).ensureSchema();
  }
}

/**
 * Wires persisted RBAC into the core authz Gate. The app provides the Prisma client (via
 * `client`, or a pre-built `store`, through `inject`/`useFactory`) — this module NEVER
 * hardcodes a connection token. On init it registers the RBAC permission check into the
 * Gate via the {@link PERMISSION_PROVIDER} seam, so `gate.allows('some.permission')`
 * consults persisted permissions. Prisma's schema is consumer-managed (no auto-create).
 */
@Module({})
export class AuthzRbacModule {
  static forRoot(options: AuthzRbacModuleOptions): DynamicModule {
    return {
      module: AuthzRbacModule,
      global: true,
      providers: [
        { provide: AUTHZ_RBAC_OPTIONS, useValue: options },
        { provide: AUTHZ_RBAC_STORE, useFactory: () => resolveStore(options) },
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
          useFactory: (opts: AuthzRbacModuleOptions) => resolveStore(opts),
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
