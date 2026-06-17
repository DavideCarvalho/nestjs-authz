import { PERMISSION_PROVIDER, type PermissionProvider } from '@dudousxd/nestjs-authz';
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
  constructor(@Inject(AUTHZ_RBAC_OPTIONS) private readonly options: AuthzRbacModuleOptions) {}

  async hasPermission(user: unknown, permission: string): Promise<boolean | undefined> {
    const map = this.options.userRefFrom ?? defaultUserRefMapper;
    const ref = map(user);
    if (ref === undefined) return undefined;
    return this.options.store.userHasPermission(ref, permission);
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
      exports: [AUTHZ_RBAC_STORE, PERMISSION_PROVIDER],
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
      exports: [AUTHZ_RBAC_STORE, PERMISSION_PROVIDER],
    };
  }

  private static commonProviders(): Provider[] {
    return [
      RbacPermissionProvider,
      { provide: PERMISSION_PROVIDER, useExisting: RbacPermissionProvider },
      AuthzRbacBootstrap,
    ];
  }
}
