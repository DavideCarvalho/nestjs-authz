import { EntityRepositoryType, EntitySchema } from '@mikro-orm/core';
import {
  AuthzPermissionRepository,
  AuthzRolePermissionRepository,
  AuthzRoleRepository,
  AuthzUserRoleRepository,
} from './repositories.js';

/**
 * Default physical table names. MikroORM resolves the table from entity metadata, so an app
 * that wants different names builds its own set of schemas with
 * {@link createAuthzEntitySchemas}; the store + schema helpers operate purely through the
 * EntityManager and read the physical names back off the live metadata.
 */
export const DEFAULT_TABLE_NAMES = {
  roles: 'authz_roles',
  permissions: 'authz_permissions',
  rolePermission: 'authz_role_permission',
  userRole: 'authz_user_role',
} as const;

/** Physical table names for the four authz tables. */
export interface AuthzTableNames {
  roles: string;
  permissions: string;
  rolePermission: string;
  userRole: string;
}

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
 *
 * `[EntityRepositoryType]` is a `declare`d marker: it carries no runtime field (the symbol is
 * skipped by MikroORM's property discovery either way) and only tells the type system what
 * `em.getRepository(RoleEntity)` returns.
 */

/**
 * A named role (e.g. `editor`). Permissions are attached via {@link RolePermissionEntity};
 * users are attached via {@link UserRoleEntity}.
 */
export class RoleEntity {
  declare [EntityRepositoryType]?: AuthzRoleRepository;
  id!: string;
  name!: string;
  guard?: string | null;
  createdAt!: Date;
}

/** A named permission (e.g. `posts.publish`). Granted to roles via {@link RolePermissionEntity}. */
export class PermissionEntity {
  declare [EntityRepositoryType]?: AuthzPermissionRepository;
  id!: string;
  name!: string;
  guard?: string | null;
  createdAt!: Date;
}

/** Pivot: role ↔ permission. Composite PK `(roleId, permissionId)`. */
export class RolePermissionEntity {
  declare [EntityRepositoryType]?: AuthzRolePermissionRepository;
  roleId!: string;
  permissionId!: string;
}

/**
 * Pivot: user ↔ role. References the user BY ID ONLY — this package NEVER defines or
 * owns a users table. `userType` lets the same table key polymorphic principals
 * (mirrors nestjs-context's `UserRef` shape).
 */
export class UserRoleEntity {
  declare [EntityRepositoryType]?: AuthzUserRoleRepository;
  userType!: string;
  userId!: string;
  roleId!: string;
}

/** The four {@link EntitySchema} definitions produced by {@link createAuthzEntitySchemas}. */
export interface AuthzEntitySchemas {
  role: EntitySchema<RoleEntity>;
  permission: EntitySchema<PermissionEntity>;
  rolePermission: EntitySchema<RolePermissionEntity>;
  userRole: EntitySchema<UserRoleEntity>;
  /** All four, in dependency order — spread into `entities: [...]`. */
  all: [
    EntitySchema<RoleEntity>,
    EntitySchema<PermissionEntity>,
    EntitySchema<RolePermissionEntity>,
    EntitySchema<UserRoleEntity>,
  ];
}

/**
 * Build the four authz {@link EntitySchema} definitions, optionally under your own table
 * names — this is the supported way to relocate the tables:
 *
 * ```ts
 * const authz = createAuthzEntitySchemas({ roles: 'app_roles' });
 * await MikroORM.init({ entities: [...authz.all] });
 * ```
 *
 * Going through the factory (rather than hand-writing `new EntitySchema({ tableName })`)
 * keeps the custom repository binding and the index names attached to the renamed tables;
 * a hand-rolled re-declaration silently drops both.
 */
export function createAuthzEntitySchemas(
  tableNames: Partial<AuthzTableNames> = {},
): AuthzEntitySchemas {
  const names: AuthzTableNames = { ...DEFAULT_TABLE_NAMES, ...tableNames };

  const role = new EntitySchema<RoleEntity>({
    class: RoleEntity,
    tableName: names.roles,
    repository: () => AuthzRoleRepository,
    properties: {
      id: { type: 'string', length: 191, primary: true },
      name: {
        type: 'string',
        length: 191,
        unique: true,
        index: `${names.roles}_name_uniq`,
      },
      guard: { type: 'string', nullable: true },
      createdAt: { type: 'datetime' },
    },
  });

  const permission = new EntitySchema<PermissionEntity>({
    class: PermissionEntity,
    tableName: names.permissions,
    repository: () => AuthzPermissionRepository,
    properties: {
      id: { type: 'string', length: 191, primary: true },
      name: {
        type: 'string',
        length: 191,
        unique: true,
        index: `${names.permissions}_name_uniq`,
      },
      guard: { type: 'string', nullable: true },
      createdAt: { type: 'datetime' },
    },
  });

  const rolePermission = new EntitySchema<RolePermissionEntity>({
    class: RolePermissionEntity,
    tableName: names.rolePermission,
    repository: () => AuthzRolePermissionRepository,
    properties: {
      roleId: { type: 'string', length: 191, primary: true },
      permissionId: { type: 'string', length: 191, primary: true },
    },
  });

  const userRole = new EntitySchema<UserRoleEntity>({
    class: UserRoleEntity,
    tableName: names.userRole,
    repository: () => AuthzUserRoleRepository,
    properties: {
      userType: { type: 'string', length: 191, primary: true },
      userId: { type: 'string', length: 191, primary: true },
      roleId: { type: 'string', length: 191, primary: true },
    },
    indexes: [{ name: `${names.userRole}_user_idx`, properties: ['userType', 'userId'] }],
  });

  return {
    role,
    permission,
    rolePermission,
    userRole,
    all: [role, permission, rolePermission, userRole],
  };
}

const defaultSchemas = createAuthzEntitySchemas();

export const RoleEntitySchema = defaultSchemas.role;
export const PermissionEntitySchema = defaultSchemas.permission;
export const RolePermissionEntitySchema = defaultSchemas.rolePermission;
export const UserRoleEntitySchema = defaultSchemas.userRole;

/**
 * All entity SCHEMAS, in dependency order — pass to `entities: [...]` registration. These
 * are the {@link EntitySchema} objects MikroORM discovers; the store keys on the plain
 * classes ({@link RoleEntity} etc.), which the schemas are bound to via `class`.
 */
export const AUTHZ_ENTITIES = defaultSchemas.all;

/**
 * The four entity CLASSES, in the same order. Pass these (not the schemas) to
 * `MikroOrmModule.forFeature()` — it matches on `meta.class`, and only then does it register
 * {@link AuthzRoleRepository} & friends as DI tokens.
 */
export const AUTHZ_ENTITY_CLASSES = [
  RoleEntity,
  PermissionEntity,
  RolePermissionEntity,
  UserRoleEntity,
] as const;
