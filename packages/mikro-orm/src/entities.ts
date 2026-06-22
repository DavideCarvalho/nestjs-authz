import { EntitySchema } from '@mikro-orm/core';

/**
 * Default table names — the {@link EntitySchema} definitions below carry these as their
 * `tableName`. MikroORM resolves the physical table from the entity metadata (not at
 * runtime), so an app that wants different names re-declares these schemas; the store +
 * schema helpers operate purely through the EntityManager and never assume a literal name.
 */
export const DEFAULT_TABLE_NAMES = {
  roles: 'authz_roles',
  permissions: 'authz_permissions',
  rolePermission: 'authz_role_permission',
  userRole: 'authz_user_role',
} as const;

/**
 * The entities are described with {@link EntitySchema} (the schema-first definition style)
 * rather than property decorators. This is the ONE definition surface that lives entirely
 * in `@mikro-orm/core` and is identical across MikroORM 6 and 7 — v7 relocated the
 * `@Entity/@Property/...` decorators to a separate `@mikro-orm/decorators` package, so a
 * decorator-based definition would force an extra peer and break on v6. The plain classes
 * below stay the public reference the store keys on (`em.find(RoleEntity, ...)`,
 * `meta.get(RoleEntity.name)`); the schemas attach metadata to them.
 *
 * Every column declares an explicit `type`, so discovery works even when the consuming app
 * compiles with SWC/esbuild/Vite (which don't emit decorator metadata — irrelevant here
 * since we don't rely on reflection, but kept explicit for clarity and parity).
 *
 * Forward-compat rule: any column added to these entities AFTER v1 MUST be nullable or
 * carry a default — `ensureAuthzSchema` only ever runs the non-destructive `safe` diff
 * (create table + add-missing-column), and `ADD COLUMN NOT NULL` without a default fails
 * on a populated table.
 */

/**
 * A named role (e.g. `editor`). Permissions are attached via {@link RolePermissionEntity};
 * users are attached via {@link UserRoleEntity}.
 */
export class RoleEntity {
  id!: string;
  name!: string;
  guard?: string | null;
  createdAt!: Date;
}

export const RoleEntitySchema = new EntitySchema<RoleEntity>({
  class: RoleEntity,
  tableName: DEFAULT_TABLE_NAMES.roles,
  properties: {
    id: { type: 'string', length: 191, primary: true },
    name: {
      type: 'string',
      length: 191,
      unique: true,
      index: 'authz_roles_name_uniq',
    },
    guard: { type: 'string', nullable: true },
    createdAt: { type: 'datetime' },
  },
});

/** A named permission (e.g. `posts.publish`). Granted to roles via {@link RolePermissionEntity}. */
export class PermissionEntity {
  id!: string;
  name!: string;
  guard?: string | null;
  createdAt!: Date;
}

export const PermissionEntitySchema = new EntitySchema<PermissionEntity>({
  class: PermissionEntity,
  tableName: DEFAULT_TABLE_NAMES.permissions,
  properties: {
    id: { type: 'string', length: 191, primary: true },
    name: {
      type: 'string',
      length: 191,
      unique: true,
      index: 'authz_permissions_name_uniq',
    },
    guard: { type: 'string', nullable: true },
    createdAt: { type: 'datetime' },
  },
});

/** Pivot: role ↔ permission. Composite PK `(roleId, permissionId)`. */
export class RolePermissionEntity {
  roleId!: string;
  permissionId!: string;
}

export const RolePermissionEntitySchema = new EntitySchema<RolePermissionEntity>({
  class: RolePermissionEntity,
  tableName: DEFAULT_TABLE_NAMES.rolePermission,
  properties: {
    roleId: { type: 'string', length: 191, primary: true },
    permissionId: { type: 'string', length: 191, primary: true },
  },
});

/**
 * Pivot: user ↔ role. References the user BY ID ONLY — this package NEVER defines or
 * owns a users table. `userType` lets the same table key polymorphic principals
 * (mirrors nestjs-context's `UserRef` shape).
 */
export class UserRoleEntity {
  userType!: string;
  userId!: string;
  roleId!: string;
}

export const UserRoleEntitySchema = new EntitySchema<UserRoleEntity>({
  class: UserRoleEntity,
  tableName: DEFAULT_TABLE_NAMES.userRole,
  properties: {
    userType: { type: 'string', length: 191, primary: true },
    userId: { type: 'string', length: 191, primary: true },
    roleId: { type: 'string', length: 191, primary: true },
  },
  indexes: [{ name: 'authz_user_role_user_idx', properties: ['userType', 'userId'] }],
});

/**
 * All entity SCHEMAS, in dependency order — pass to `entities: [...]` registration. These
 * are the {@link EntitySchema} objects MikroORM discovers; the store keys on the plain
 * classes ({@link RoleEntity} etc.), which the schemas are bound to via `class`.
 */
export const AUTHZ_ENTITIES = [
  RoleEntitySchema,
  PermissionEntitySchema,
  RolePermissionEntitySchema,
  UserRoleEntitySchema,
] as const;
