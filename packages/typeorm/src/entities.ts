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
} as const;

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
 */
@Entity({ name: DEFAULT_TABLE_NAMES.userRole })
@Index(['userType', 'userId'])
export class UserRoleEntity {
  @PrimaryColumn({ type: 'varchar', length: 191 })
  userType!: string;

  @PrimaryColumn({ type: 'varchar', length: 191 })
  userId!: string;

  @PrimaryColumn({ type: 'varchar', length: 191 })
  roleId!: string;
}

/** All entities, in dependency order — convenient for `entities: [...]` registration. */
export const AUTHZ_ENTITIES = [
  RoleEntity,
  PermissionEntity,
  RolePermissionEntity,
  UserRoleEntity,
] as const;
