import { randomUUID } from 'node:crypto';
import {
  DEFAULT_ROLE_SOURCE,
  type RoleAssignment,
  type UserAuthz,
  type UserRef,
  normalizeUserRef,
} from '@dudousxd/nestjs-authz/store-kit';
import type { EntityManager, MikroORM } from '@mikro-orm/core';
import { PermissionEntity, RoleEntity, RolePermissionEntity, UserRoleEntity } from './entities.js';
import { ensureAuthzSchema } from './schema.js';

// Re-exported so `@dudousxd/nestjs-authz-mikro-orm`'s public `UserAuthz` keeps the
// same import path; canonical definition lives in core's store-kit.
export type { RoleAssignment, UserAuthz };

/** Assignment source for role mutations (default `'manual'`) — see `setUserRoles`. */
export interface RoleSourceOptions {
  source?: string;
}

/**
 * MikroORM-backed RBAC store. A plain POJO that receives the `EntityManager` in its
 * constructor — NOT `@Injectable`, no internal connection token (the app owns the
 * connection and plugs it via DI; see the persistence contract).
 *
 * The store works purely through the EntityManager + the registered entities, so it never
 * assumes a literal table name — names are owned by the entity metadata. Every read forks
 * the EM (`this.em.fork()`) so it is request-safe under MikroORM's identity-map rules.
 */
export class MikroOrmAuthzStore {
  // `opts` is reserved for forward-compat (parity with the TypeORM adapter's options); it is
  // accepted but not yet consumed since MikroORM owns table names via entity metadata.
  constructor(
    private readonly em: EntityManager,
    _opts: Record<string, never> = {},
  ) {}

  /** Create/upgrade the RBAC tables (non-destructive, delegates to {@link ensureAuthzSchema}). */
  ensureSchema(): Promise<void> {
    return ensureAuthzSchema(this.em);
  }

  // --- roles & permissions (idempotent upserts by name) ---

  /**
   * Create the role if absent; returns its id. Idempotent and race-tolerant: it re-reads
   * by the unique `name` after a create so two concurrent creators converge on the same row.
   */
  async createRole(name: string): Promise<string> {
    const existing = await this.findRoleId(name);
    if (existing) return existing;
    const em = this.em.fork();
    const entity = em.create(RoleEntity, {
      id: randomUUID(),
      name,
      guard: null,
      createdAt: new Date(),
    });
    try {
      await em.persist(entity).flush();
    } catch {
      // A concurrent insert won the race on the unique `name`; fall through to re-read.
    }
    const id = await this.findRoleId(name);
    if (!id) throw new Error(`Failed to create or resolve role "${name}".`);
    return id;
  }

  /** Create the permission if absent; returns its id. Idempotent and race-tolerant. */
  async createPermission(name: string): Promise<string> {
    const existing = await this.findPermissionId(name);
    if (existing) return existing;
    const em = this.em.fork();
    const entity = em.create(PermissionEntity, {
      id: randomUUID(),
      name,
      guard: null,
      createdAt: new Date(),
    });
    try {
      await em.persist(entity).flush();
    } catch {
      // A concurrent insert won the race on the unique `name`; fall through to re-read.
    }
    const id = await this.findPermissionId(name);
    if (!id) throw new Error(`Failed to create or resolve permission "${name}".`);
    return id;
  }

  private async findRoleId(name: string): Promise<string | undefined> {
    const row = await this.em.fork().findOne(RoleEntity, { name });
    return row?.id;
  }

  private async findPermissionId(name: string): Promise<string | undefined> {
    const row = await this.em.fork().findOne(PermissionEntity, { name });
    return row?.id;
  }

  // --- role ↔ permission ---

  /** Grant a permission to a role (creating both by name if needed). Idempotent. */
  async givePermissionToRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.createRole(roleName);
    const permissionId = await this.createPermission(permissionName);
    const em = this.em.fork();
    const existing = await em.findOne(RolePermissionEntity, { roleId, permissionId });
    if (existing) return;
    em.create(RolePermissionEntity, { roleId, permissionId });
    await em.flush();
  }

  /** Revoke a permission from a role. No-op if either is absent or not linked. */
  async revokePermissionFromRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.findRoleId(roleName);
    const permissionId = await this.findPermissionId(permissionName);
    if (!roleId || !permissionId) return;
    await this.em.fork().nativeDelete(RolePermissionEntity, { roleId, permissionId });
  }

  // --- user ↔ role ---

  /**
   * Assign a role to a user (creating the role by name if needed). Idempotent. `{ source }`
   * (default `'manual'`) records where the assignment came from.
   */
  async assignRole(user: UserRef, roleName: string, opts?: RoleSourceOptions): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.createRole(roleName);
    const source = opts?.source ?? DEFAULT_ROLE_SOURCE;
    const em = this.em.fork();
    const existing = await em.findOne(UserRoleEntity, {
      userType: type,
      userId: id,
      roleId,
      source,
    });
    if (existing) return;
    em.create(UserRoleEntity, { userType: type, userId: id, roleId, source });
    await em.flush();
  }

  /**
   * Remove a role from a user. No-op if the role or assignment is absent. With `{ source }` only
   * that source's assignment goes; without it, the role is removed from every source.
   */
  async removeRole(user: UserRef, roleName: string, opts?: RoleSourceOptions): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    await this.em.fork().nativeDelete(UserRoleEntity, {
      userType: type,
      userId: id,
      roleId,
      ...(opts?.source !== undefined ? { source: opts.source } : {}),
    });
  }

  /**
   * REPLACE the user's role assignments of ONE source (default `'manual'`) with exactly
   * `roleNames` — e.g. an SSO/SCIM sync calls `setUserRoles(user, mappedRoles, { source: 'sso' })`
   * on every login. Other sources' assignments are untouched, so a role held both manually and via
   * SSO survives an SSO sync that drops it. Roles are created by name when missing. Transactional.
   */
  async setUserRoles(
    user: UserRef,
    roleNames: readonly string[],
    opts?: RoleSourceOptions,
  ): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const source = opts?.source ?? DEFAULT_ROLE_SOURCE;
    const roleIds: string[] = [];
    for (const name of new Set(roleNames)) roleIds.push(await this.createRole(name));
    await this.em.fork().transactional(async (tx) => {
      await tx.nativeDelete(UserRoleEntity, { userType: type, userId: id, source });
      for (const roleId of roleIds) {
        tx.create(UserRoleEntity, { userType: type, userId: id, roleId, source });
      }
      await tx.flush();
    });
  }

  /** Every role assignment of a user, one entry per `(role, source)`. */
  async getRoleAssignments(user: UserRef): Promise<RoleAssignment[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const assignments = await em.find(UserRoleEntity, { userType: type, userId: id });
    if (assignments.length === 0) return [];
    const roles = await em.find(RoleEntity, { id: { $in: assignments.map((a) => a.roleId) } });
    const nameById = new Map(roles.map((r) => [r.id, r.name]));
    return assignments
      .filter((a) => nameById.has(a.roleId))
      .map((a) => ({ role: nameById.get(a.roleId) as string, source: a.source, tenantId: null }))
      .sort((a, b) => a.role.localeCompare(b.role) || a.source.localeCompare(b.source));
  }

  // --- queries ---

  /** The role names a user holds. */
  async getRolesForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const assignments = await em.find(UserRoleEntity, { userType: type, userId: id });
    if (assignments.length === 0) return [];
    const roleIds = assignments.map((a) => a.roleId);
    const roles = await em.find(RoleEntity, { id: { $in: roleIds } });
    return roles.map((r) => r.name);
  }

  /**
   * The flattened, distinct permission names a user has via their roles.
   *
   * Resolved in a SINGLE database round-trip via a `permission ← rolePermission ← userRole`
   * join (previously three sequential `find` calls). Table/column names are read from the
   * live entity metadata (not hard-coded) so re-decorated table names keep working. The
   * returned set is the FULL granted permission name set, deduped — callers (incl. the
   * wildcard matcher) rely on getting every granted name (e.g. a granted `posts.*`).
   */
  async getPermissionsForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();

    // Derive physical table + column names from metadata so we honor re-decorated entities.
    const meta = em.getMetadata();
    const perm = meta.get(PermissionEntity.name);
    const rolePerm = meta.get(RolePermissionEntity.name);
    const userRole = meta.get(UserRoleEntity.name);

    /** First physical column name for an entity property, from live metadata. */
    const col = (m: typeof perm, prop: string): string => {
      const field = m.properties[prop]?.fieldNames?.[0];
      if (!field) throw new Error(`Missing column metadata for ${m.className}.${prop}`);
      return field;
    };

    const permTable = perm.tableName;
    const permId = col(perm, 'id');
    const permName = col(perm, 'name');
    const rpTable = rolePerm.tableName;
    const rpRoleId = col(rolePerm, 'roleId');
    const rpPermId = col(rolePerm, 'permissionId');
    const urTable = userRole.tableName;
    const urRoleId = col(userRole, 'roleId');
    const urUserType = col(userRole, 'userType');
    const urUserId = col(userRole, 'userId');

    // Single round-trip: permission ← rolePermission ← userRole. Identifiers come from
    // entity metadata (trusted), values are bound as parameters (no SQL injection surface).
    const sql =
      `select distinct p.${permName} as name ` +
      `from ${permTable} p ` +
      `inner join ${rpTable} rp on rp.${rpPermId} = p.${permId} ` +
      `inner join ${urTable} ur on ur.${urRoleId} = rp.${rpRoleId} ` +
      `where ur.${urUserType} = ? and ur.${urUserId} = ?`;

    const rows = (await em.getConnection().execute(sql, [type, id])) as Array<{ name: string }>;
    return [...new Set(rows.map((r) => r.name))];
  }

  /** A user's roles + effective permissions in one shot. */
  async getUserAuthz(user: UserRef): Promise<UserAuthz> {
    const [roles, permissions] = await Promise.all([
      this.getRolesForUser(user),
      this.getPermissionsForUser(user),
    ]);
    return { roles, permissions };
  }

  /** True when the user holds `permission` through any of their roles. */
  async userHasPermission(user: UserRef, permission: string): Promise<boolean> {
    const permissions = await this.getPermissionsForUser(user);
    return permissions.includes(permission);
  }
}
