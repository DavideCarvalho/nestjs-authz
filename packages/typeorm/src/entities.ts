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
