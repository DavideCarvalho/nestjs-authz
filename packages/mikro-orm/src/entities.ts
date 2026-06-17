import { Entity, Index, PrimaryKey, Property } from '@mikro-orm/core';

/**
 * Default table names — the entities below carry these as their `tableName`. MikroORM
 * resolves the physical table from the entity metadata (not at runtime), so an app that
 * wants different names re-decorates these entities; the store + schema helpers operate
 * purely through the EntityManager and never assume a literal name.
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
 * Every column declares an explicit `type` instead of relying on `emitDecoratorMetadata`
 * reflection, so the entity discovers correctly even when the consuming app compiles with
 * SWC/esbuild/Vite (which don't emit decorator metadata).
 *
 * Forward-compat rule: any column added to these entities AFTER v1 MUST be nullable or
 * carry a default — `ensureAuthzSchema` only ever runs the non-destructive `safe` diff
 * (create table + add-missing-column), and `ADD COLUMN NOT NULL` without a default fails
 * on a populated table.
 */
@Entity({ tableName: DEFAULT_TABLE_NAMES.roles })
export class RoleEntity {
  @PrimaryKey({ type: 'string', length: 191 })
  id!: string;

  @Index({ name: 'authz_roles_name_uniq' })
  @Property({ type: 'string', length: 191, unique: true })
  name!: string;

  @Property({ type: 'string', nullable: true })
  guard?: string | null;

  @Property({ type: 'datetime' })
  createdAt!: Date;
}

/** A named permission (e.g. `posts.publish`). Granted to roles via {@link RolePermissionEntity}. */
@Entity({ tableName: DEFAULT_TABLE_NAMES.permissions })
export class PermissionEntity {
  @PrimaryKey({ type: 'string', length: 191 })
  id!: string;

  @Index({ name: 'authz_permissions_name_uniq' })
  @Property({ type: 'string', length: 191, unique: true })
  name!: string;

  @Property({ type: 'string', nullable: true })
  guard?: string | null;

  @Property({ type: 'datetime' })
  createdAt!: Date;
}

/** Pivot: role ↔ permission. Composite PK `(roleId, permissionId)`. */
@Entity({ tableName: DEFAULT_TABLE_NAMES.rolePermission })
export class RolePermissionEntity {
  @PrimaryKey({ type: 'string', length: 191 })
  roleId!: string;

  @PrimaryKey({ type: 'string', length: 191 })
  permissionId!: string;
}

/**
 * Pivot: user ↔ role. References the user BY ID ONLY — this package NEVER defines or
 * owns a users table. `userType` lets the same table key polymorphic principals
 * (mirrors nestjs-context's `UserRef` shape).
 */
@Entity({ tableName: DEFAULT_TABLE_NAMES.userRole })
@Index({ name: 'authz_user_role_user_idx', properties: ['userType', 'userId'] })
export class UserRoleEntity {
  @PrimaryKey({ type: 'string', length: 191 })
  userType!: string;

  @PrimaryKey({ type: 'string', length: 191 })
  userId!: string;

  @PrimaryKey({ type: 'string', length: 191 })
  roleId!: string;
}

/** All entities, in dependency order — convenient for `entities: [...]` registration. */
export const AUTHZ_ENTITIES = [
  RoleEntity,
  PermissionEntity,
  RolePermissionEntity,
  UserRoleEntity,
] as const;
