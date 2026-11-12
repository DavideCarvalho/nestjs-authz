import { assertSafeIdentifier } from '@dudousxd/nestjs-authz';
import { DEFAULT_ROLE_SOURCE } from '@dudousxd/nestjs-authz/store-kit';
import { Column, Entity, Index, PrimaryColumn } from 'typeorm';

/**
 * Default table names. Override per-deployment via {@link AuthzStoreOptions.tableNames}
 * — the entities below carry these as their decorator defaults so an app that manages
 * the schema through its own ORM gets sane names out of the box, while BYO names flow
 * through the store/schema helpers at runtime.
 */
export const DEFAULT_TABLE_NAMES = {
  roles: 'authz_roles',
  permissions: 'authz_permissions',
  rolePermission: 'authz_role_permission',
  userRole: 'authz_user_role',
  userPermission: 'authz_user_permission',
} as const;

/**
 * The "no tenant" sentinel for the user-role pivot's `tenantId`. A GLOBAL (unscoped)
 * assignment stores this empty string rather than `NULL` so the column stays part of
 * the composite primary key with portable, dialect-correct uniqueness (SQL treats
 * `NULL`s as distinct, which would break idempotency of a global grant and silently
 * permit duplicates). The column is added post-v1 with a default of this value, so an
 * older populated table self-heals via `ensureAuthzSchema` (`ADD COLUMN ... DEFAULT ''`).
 */
export const GLOBAL_TENANT = '';

/**
 * A named role (e.g. `editor`). Permissions are attached via {@link RolePermissionEntity};
 * users are attached via {@link UserRoleEntity}.
 *
 * Forward-compat rule: any column added to these entities AFTER v1 MUST be nullable or
 * carry a default — `ADD COLUMN NOT NULL` without a default fails on a populated table,
 * and {@link ensureAuthzSchema} only ever ADDs columns.
 */
@Entity({ name: DEFAULT_TABLE_NAMES.roles })
export class RoleEntity {
  @PrimaryColumn({ type: 'varchar', length: 191 })
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 191 })
  name!: string;

  @Column({ type: 'varchar', nullable: true })
  guard!: string | null;

  @Column({ type: Date })
  createdAt!: Date;
}

/** A named permission (e.g. `posts.publish`). Granted to roles via {@link RolePermissionEntity}. */
@Entity({ name: DEFAULT_TABLE_NAMES.permissions })
export class PermissionEntity {
  @PrimaryColumn({ type: 'varchar', length: 191 })
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 191 })
  name!: string;

  @Column({ type: 'varchar', nullable: true })
  guard!: string | null;

  @Column({ type: Date })
  createdAt!: Date;
}

/** Pivot: role ↔ permission. Composite PK `(roleId, permissionId)`. */
@Entity({ name: DEFAULT_TABLE_NAMES.rolePermission })
export class RolePermissionEntity {
  @PrimaryColumn({ type: 'varchar', length: 191 })
  roleId!: string;

  @PrimaryColumn({ type: 'varchar', length: 191 })
  permissionId!: string;
}

/**
 * Pivot: user ↔ role. References the user BY ID ONLY — this package NEVER defines or
 * owns a users table. `userType` lets the same table key polymorphic principals
 * (mirrors nestjs-context's `UserRef` shape).
 *
 * `tenantId` (post-v1, defaulted to {@link GLOBAL_TENANT} = `''`) scopes the
 * assignment to a tenant: an empty value = global (applies in every tenant), a
 * non-empty value = only within that tenant. It is part of the composite PK so the
 * same `(user, role)` can be granted independently in multiple tenants while staying
 * idempotent per tenant. Defaulted (not nullable) so the column belongs to the PK
 * with portable uniqueness — see {@link GLOBAL_TENANT}.
 */
@Entity({ name: DEFAULT_TABLE_NAMES.userRole })
@Index(['userType', 'userId'])
export class UserRoleEntity {
  @PrimaryColumn({ type: 'varchar', length: 191 })
  userType!: string;

  @PrimaryColumn({ type: 'varchar', length: 191 })
  userId!: string;

  // 64 (not 191): role ids are store-generated UUIDs, and the 5-column PK must stay under
  // MySQL/utf8mb4's 3072-byte index limit (191+191+64+191+64 chars × 4 bytes = 2804).
  @PrimaryColumn({ type: 'varchar', length: 64 })
  roleId!: string;

  @PrimaryColumn({ type: 'varchar', length: 191, default: GLOBAL_TENANT })
  tenantId!: string;

  /**
   * Where the assignment came from (`'manual'`, `'sso'`, `'scim'`, …). Part of the PK on tables
   * created by this version, so the same role can be held through two sources (removing one keeps
   * the role). On OLDER tables `ensureAuthzSchema` adds it as a plain defaulted column (existing
   * rows become manual assignments) and never touches the existing primary key — widen it with the
   * migration in the README to allow one role from two sources.
   */
  @PrimaryColumn({ type: 'varchar', length: 64, default: DEFAULT_ROLE_SOURCE })
  source!: string;
}

/**
 * Pivot: user ↔ permission (a DIRECT grant, no role needed — Laravel/spatie's
 * `$user->givePermissionTo(...)`). Mirrors {@link UserRoleEntity}: the user is
 * referenced BY ID ONLY and `userType` keys polymorphic principals. Composite PK
 * `(userType, userId, permissionId)`.
 */
@Entity({ name: DEFAULT_TABLE_NAMES.userPermission })
@Index(['userType', 'userId'])
export class UserPermissionEntity {
  @PrimaryColumn({ type: 'varchar', length: 191 })
  userType!: string;

  @PrimaryColumn({ type: 'varchar', length: 191 })
  userId!: string;

  @PrimaryColumn({ type: 'varchar', length: 191 })
  permissionId!: string;
}

/** All entities, in dependency order — convenient for `entities: [...]` registration. */
export const AUTHZ_ENTITIES = [
  RoleEntity,
  PermissionEntity,
  RolePermissionEntity,
  UserRoleEntity,
  UserPermissionEntity,
] as const;

/** Options for {@link authzEntities}. */
export interface AuthzEntitiesOptions {
  /**
   * Put the tables in this schema: a Postgres schema, or a MySQL database. Every query and DDL
   * statement names it; `search_path` is never used.
   */
  schema?: string;
  /** The connection's database type: `schema` becomes the entities' `schema` on Postgres and their `database` on MySQL. Default `'postgres'`. */
  type?: 'postgres' | 'mysql';
  /** BYO table names, like the store's `tableNames`. */
  tableNames?: Partial<Record<keyof typeof DEFAULT_TABLE_NAMES, string>>;
}

const BASES = {
  roles: RoleEntity,
  permissions: PermissionEntity,
  rolePermission: RolePermissionEntity,
  userRole: UserRoleEntity,
  userPermission: UserPermissionEntity,
} as const;

/**
 * The authz entities under your table names and schema, for a DataSource whose `synchronize` or
 * migrations generator manages them. Register these INSTEAD of {@link AUTHZ_ENTITIES} and pass
 * the same `schema` / `tableNames` to the store:
 *
 * ```ts
 * const entities = authzEntities({ schema: 'authz' });
 * new DataSource({ type: 'postgres', entities: [...entities, ...appEntities] });
 * new TypeOrmAuthzStore(dataSource, { schema: 'authz' });
 * ```
 */
export function authzEntities(
  options: AuthzEntitiesOptions = {},
): [
  typeof RoleEntity,
  typeof PermissionEntity,
  typeof RolePermissionEntity,
  typeof UserRoleEntity,
  typeof UserPermissionEntity,
] {
  const { schema, type = 'postgres', tableNames = {} } = options;
  if (schema !== undefined) assertSchemaName(schema);
  const make = <K extends keyof typeof BASES>(key: K): (typeof BASES)[K] => {
    const name = tableNames[key] ?? DEFAULT_TABLE_NAMES[key];
    assertSafeIdentifier(name, `table name (${key})`);
    const base = BASES[key] as unknown as new () => object;
    // A subclass per call: TypeORM reads the columns from the decorated base class.
    const entity = class extends base {};
    Object.defineProperty(entity, 'name', { value: base.name });
    const where = schema === undefined ? {} : type === 'mysql' ? { database: schema } : { schema };
    Entity({ name, ...where })(entity);
    return entity as unknown as (typeof BASES)[K];
  };
  return [
    make('roles'),
    make('permissions'),
    make('rolePermission'),
    make('userRole'),
    make('userPermission'),
  ];
}

/**
 * Validate a `schema` option: a safe identifier (letters, digits, `_`, not starting with a
 * digit) of at most 63 characters (the Postgres limit; MySQL allows 64).
 */
export function assertSchemaName(schema: string): void {
  assertSafeIdentifier(schema, 'schema name');
  if (schema.length > 63) {
    throw new Error(`Schema name ${JSON.stringify(schema)} is longer than 63 characters.`);
  }
}
