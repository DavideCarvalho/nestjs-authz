import { randomUUID } from 'node:crypto';
import {
  DEFAULT_ROLE_SOURCE,
  type RoleAssignment,
  type RoleAssignmentFilter,
  type UserAuthz,
  type UserRef,
  type UserRoleAssignment,
  compareUserRoleAssignments,
  normalizeUserRef,
  roleFilterNames,
} from '@dudousxd/nestjs-authz/store-kit';
import { type SQL, and, eq, inArray, sql } from 'drizzle-orm';
import { type AuthzTables, GLOBAL_TENANT, authzSchemaDdl, createAuthzTables } from './schema.js';
import type {
  AuthzStoreOptions,
  DrizzlePgDatabase,
  RoleAssignmentScope,
  TenantScope,
} from './types.js';

// Re-exported so `@dudousxd/nestjs-authz-drizzle`'s public `UserAuthz` keeps the same import
// path; canonical definition lives in core's store-kit.
export type { RoleAssignment, RoleAssignmentFilter, UserAuthz, UserRoleAssignment };

/**
 * Drizzle-backed RBAC store (Postgres). A plain POJO that receives the app's Drizzle database in
 * its constructor — NOT `@Injectable`, no internal connection token (the app owns the connection
 * and plugs it via DI; see the persistence contract). Same method surface as the TypeORM adapter:
 * idempotent role/permission upserts, tenant-scoped role assignments, direct user permissions.
 *
 * Every statement goes through the Drizzle query builder, so values are always bound and the
 * table identifiers come from the (validated) Drizzle table config. Pass a transaction (`tx`) as
 * `db` to run the store inside the caller's unit of work.
 */
export class DrizzleAuthzStore {
  /** The Drizzle tables this store reads/writes (spread them into your drizzle-kit schema). */
  readonly tables: AuthzTables;

  constructor(
    private readonly db: DrizzlePgDatabase,
    opts: AuthzStoreOptions = {},
  ) {
    const buildOpts: Parameters<typeof createAuthzTables>[0] = {};
    if (opts.tableNames !== undefined) buildOpts.tableNames = opts.tableNames;
    if (opts.schema !== undefined) buildOpts.schema = opts.schema;
    this.tables = opts.tables ?? createAuthzTables(buildOpts);
  }

  /** A store bound to another database/transaction, sharing this store's tables. */
  withDb(db: DrizzlePgDatabase): DrizzleAuthzStore {
    return new DrizzleAuthzStore(db, { tables: this.tables });
  }

  /**
   * Create the RBAC tables if they don't exist (`CREATE ... IF NOT EXISTS`, never destructive).
   * Skip this when drizzle-kit owns your migrations — spread {@link AuthzStoreOptions.tables}
   * into your schema instead.
   */
  async ensureSchema(): Promise<void> {
    for (const statement of authzSchemaDdl(this.tables)) {
      await this.db.execute(sql.raw(statement));
    }
  }

  // --- roles & permissions (idempotent upserts by name) ---

  /**
   * Create the role if absent; returns its id. Idempotent and race-tolerant: the INSERT is
   * `ON CONFLICT DO NOTHING` on the unique `name`, and the id is re-read afterwards so two
   * concurrent creators converge on the same row.
   */
  async createRole(name: string): Promise<string> {
    const existing = await this.findRoleId(name);
    if (existing) return existing;
    const { roles } = this.tables;
    await this.db
      .insert(roles)
      .values({ id: randomUUID(), name, guard: null, createdAt: new Date() })
      .onConflictDoNothing();
    const id = await this.findRoleId(name);
    if (!id) throw new Error(`Failed to create or resolve role "${name}".`);
    return id;
  }

  /** Create the permission if absent; returns its id. Idempotent and race-tolerant. */
  async createPermission(name: string): Promise<string> {
    const existing = await this.findPermissionId(name);
    if (existing) return existing;
    const { permissions } = this.tables;
    await this.db
      .insert(permissions)
      .values({ id: randomUUID(), name, guard: null, createdAt: new Date() })
      .onConflictDoNothing();
    const id = await this.findPermissionId(name);
    if (!id) throw new Error(`Failed to create or resolve permission "${name}".`);
    return id;
  }

  private async findRoleId(name: string): Promise<string | undefined> {
    const { roles } = this.tables;
    const rows = await this.db
      .select({ id: roles.id })
      .from(roles)
      .where(eq(roles.name, name))
      .limit(1);
    return rows[0]?.id;
  }

  private async findPermissionId(name: string): Promise<string | undefined> {
    const { permissions } = this.tables;
    const rows = await this.db
      .select({ id: permissions.id })
      .from(permissions)
      .where(eq(permissions.name, name))
      .limit(1);
    return rows[0]?.id;
  }

  // --- role ↔ permission ---

  /** Grant a permission to a role (creating both by name if needed). Idempotent. */
  async givePermissionToRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.createRole(roleName);
    const permissionId = await this.createPermission(permissionName);
    await this.db
      .insert(this.tables.rolePermission)
      .values({ roleId, permissionId })
      .onConflictDoNothing();
  }

  /** Revoke a permission from a role. No-op if either is absent or not linked. */
  async revokePermissionFromRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.findRoleId(roleName);
    const permissionId = await this.findPermissionId(permissionName);
    if (!roleId || !permissionId) return;
    const { rolePermission } = this.tables;
    await this.db
      .delete(rolePermission)
      .where(and(eq(rolePermission.roleId, roleId), eq(rolePermission.permissionId, permissionId)));
  }

  /**
   * Delete a role together with its role→permission links and EVERY user assignment of it (all
   * tenants, all sources), in one transaction. Returns whether the role existed. The permissions
   * themselves are kept (other roles or direct grants may use them).
   */
  async deleteRole(roleName: string): Promise<boolean> {
    const { roles, rolePermission, userRole } = this.tables;
    return this.db.transaction(async (tx) => {
      const rows = await tx.select({ id: roles.id }).from(roles).where(eq(roles.name, roleName));
      const roleId = rows[0]?.id;
      if (!roleId) return false;
      await tx.delete(userRole).where(eq(userRole.roleId, roleId));
      await tx.delete(rolePermission).where(eq(rolePermission.roleId, roleId));
      await tx.delete(roles).where(eq(roles.id, roleId));
      return true;
    });
  }

  /**
   * REPLACE the role's permission set with exactly `permissionNames` (spatie's
   * `syncPermissions`): links not in the list are removed, missing ones added. The role and the
   * permissions are created by name when missing. Runs in one transaction (or inside the
   * caller's, when the store was built with `tx`). An empty list leaves the role with no
   * permissions.
   */
  async syncRolePermissions(roleName: string, permissionNames: readonly string[]): Promise<void> {
    const { rolePermission } = this.tables;
    await this.db.transaction(async (tx) => {
      const store = this.withDb(tx);
      const roleId = await store.createRole(roleName);
      const permissionIds: string[] = [];
      for (const name of new Set(permissionNames)) {
        permissionIds.push(await store.createPermission(name));
      }
      await tx.delete(rolePermission).where(eq(rolePermission.roleId, roleId));
      if (permissionIds.length > 0) {
        await tx
          .insert(rolePermission)
          .values(permissionIds.map((permissionId) => ({ roleId, permissionId })))
          .onConflictDoNothing();
      }
    });
  }

  /**
   * The permission names of each named role, in one query. Every EXISTING requested role is a
   * key (mapped to `[]` when it has no permissions); roles that don't exist are ABSENT from the
   * result. Names are sorted.
   */
  async getRolePermissions(roleNames: readonly string[]): Promise<Record<string, string[]>> {
    const names = [...new Set(roleNames)];
    const out: Record<string, string[]> = {};
    if (names.length === 0) return out;
    const { roles, permissions, rolePermission } = this.tables;
    const rows = await this.db
      .select({ role: roles.name, permission: permissions.name })
      .from(roles)
      .leftJoin(rolePermission, eq(rolePermission.roleId, roles.id))
      .leftJoin(permissions, eq(permissions.id, rolePermission.permissionId))
      .where(inArray(roles.name, names));
    for (const row of rows) {
      let list = out[row.role];
      if (!list) {
        list = [];
        out[row.role] = list;
      }
      if (row.permission !== null) list.push(row.permission);
    }
    for (const list of Object.values(out)) list.sort();
    return out;
  }

  // --- user ↔ role ---

  /**
   * Assign a role to a user (creating the role by name if needed). Idempotent.
   *
   * Pass `{ tenantId }` to scope the assignment to a tenant — it then applies ONLY within that
   * tenant. Omitting it makes a GLOBAL assignment that applies in every tenant (and in an
   * unscoped check). The same `(user, role)` can be assigned in multiple tenants independently.
   */
  async assignRole(user: UserRef, roleName: string, scope?: RoleAssignmentScope): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.createRole(roleName);
    await this.db
      .insert(this.tables.userRole)
      .values({
        userType: type,
        userId: id,
        roleId,
        tenantId: scope?.tenantId ?? GLOBAL_TENANT,
        source: scope?.source ?? DEFAULT_ROLE_SOURCE,
      })
      .onConflictDoNothing();
  }

  /**
   * REPLACE the user's role assignments of ONE source (default `'manual'`) in one tenant scope
   * with exactly `roleNames` — e.g. an SSO/SCIM sync calls `setUserRoles(user, mappedRoles,
   * { source: 'sso' })` on every login. Other sources' assignments are untouched, so a role held
   * both manually and via SSO survives an SSO sync that drops it. Roles are created by name when
   * missing. Runs in a transaction (or inside the caller's, when the store was built with `tx`).
   */
  async setUserRoles(
    user: UserRef,
    roleNames: readonly string[],
    scope?: RoleAssignmentScope,
  ): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    const source = scope?.source ?? DEFAULT_ROLE_SOURCE;
    const roleIds: string[] = [];
    for (const name of new Set(roleNames)) roleIds.push(await this.createRole(name));
    const { userRole } = this.tables;
    await this.db.transaction(async (tx) => {
      await tx
        .delete(userRole)
        .where(
          and(
            eq(userRole.userType, type),
            eq(userRole.userId, id),
            eq(userRole.tenantId, tenantId),
            eq(userRole.source, source),
          ),
        );
      if (roleIds.length > 0) {
        await tx
          .insert(userRole)
          .values(
            roleIds.map((roleId) => ({ userType: type, userId: id, roleId, tenantId, source })),
          )
          .onConflictDoNothing();
      }
    });
  }

  /**
   * Remove a role from a user. No-op if the role or assignment is absent. With `{ tenantId }`
   * only the assignment in THAT tenant is removed; omitting it removes the GLOBAL assignment.
   * With `{ source }` only that source's assignment goes; without it, every source's.
   */
  async removeRole(user: UserRef, roleName: string, scope?: RoleAssignmentScope): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    const { userRole } = this.tables;
    await this.db
      .delete(userRole)
      .where(
        and(
          eq(userRole.userType, type),
          eq(userRole.userId, id),
          eq(userRole.roleId, roleId),
          eq(userRole.tenantId, scope?.tenantId ?? GLOBAL_TENANT),
          scope?.source !== undefined ? eq(userRole.source, scope.source) : undefined,
        ),
      );
  }

  /**
   * Delete every role assignment (all tenants, all sources) and every DIRECT permission of the
   * user — e.g. when the account is deleted. One transaction. Roles and permissions are kept.
   */
  async removeUser(user: UserRef): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const { userRole, userPermission } = this.tables;
    await this.db.transaction(async (tx) => {
      await tx.delete(userRole).where(and(eq(userRole.userType, type), eq(userRole.userId, id)));
      await tx
        .delete(userPermission)
        .where(and(eq(userPermission.userType, type), eq(userPermission.userId, id)));
    });
  }

  // --- user ↔ permission (DIRECT grant, no role) ---

  /** Grant a permission DIRECTLY to a user (spatie's `$user->givePermissionTo`). Idempotent. */
  async giveUserPermission(user: UserRef, permissionName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const permissionId = await this.createPermission(permissionName);
    await this.db
      .insert(this.tables.userPermission)
      .values({ userType: type, userId: id, permissionId })
      .onConflictDoNothing();
  }

  /**
   * Revoke a DIRECT user permission. No-op if absent. Only the direct grant is removed — a
   * permission the user ALSO has via a role survives.
   */
  async revokeUserPermission(user: UserRef, permissionName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const permissionId = await this.findPermissionId(permissionName);
    if (!permissionId) return;
    const { userPermission } = this.tables;
    await this.db
      .delete(userPermission)
      .where(
        and(
          eq(userPermission.userType, type),
          eq(userPermission.userId, id),
          eq(userPermission.permissionId, permissionId),
        ),
      );
  }

  // --- queries ---

  /**
   * Role assignments visible for a tenant scope: a GLOBAL assignment always applies; a
   * tenant-scoped one only when its tenant matches. With no tenant, only global assignments are
   * visible (a tenant-scoped role never leaks into an unscoped check).
   */
  private tenantFilter(scope: TenantScope | undefined): SQL {
    const { userRole } = this.tables;
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    return tenantId === GLOBAL_TENANT
      ? eq(userRole.tenantId, GLOBAL_TENANT)
      : inArray(userRole.tenantId, [GLOBAL_TENANT, tenantId]);
  }

  private userRoleWhere(type: string, id: string, scope: TenantScope | undefined): SQL {
    const { userRole } = this.tables;
    return and(
      eq(userRole.userType, type),
      eq(userRole.userId, id),
      this.tenantFilter(scope),
    ) as SQL;
  }

  /** The role names a user holds, optionally restricted to a tenant scope (see {@link assignRole}). */
  async getRolesForUser(user: UserRef, scope?: TenantScope): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const { roles, userRole } = this.tables;
    const rows = await this.db
      .selectDistinct({ name: roles.name })
      .from(userRole)
      .innerJoin(roles, eq(roles.id, userRole.roleId))
      .where(this.userRoleWhere(type, id, scope));
    return rows.map((row) => row.name);
  }

  /**
   * Every role assignment visible in a tenant scope, one entry per `(role, source, tenant)` —
   * e.g. to show which roles came from SSO and which were granted by hand.
   */
  async getRoleAssignments(user: UserRef, scope?: TenantScope): Promise<RoleAssignment[]> {
    const { type, id } = normalizeUserRef(user);
    const { roles, userRole } = this.tables;
    const rows = await this.db
      .select({ role: roles.name, source: userRole.source, tenantId: userRole.tenantId })
      .from(userRole)
      .innerJoin(roles, eq(roles.id, userRole.roleId))
      .where(this.userRoleWhere(type, id, scope))
      .orderBy(roles.name, userRole.source);
    return rows.map((row) => ({
      role: row.role,
      source: row.source,
      tenantId: row.tenantId === GLOBAL_TENANT ? null : row.tenantId,
    }));
  }

  /**
   * Raw role-assignment rows for admin listings — e.g. every member's roles in a tenant with
   * their sources (`{ tenantId: 'acme' }`), or who holds a role (`{ role: 'admin' }`).
   *
   * `tenantId`: omitted = no tenant filter; `null` = GLOBAL assignments only; a string = exactly
   * that tenant's scoped assignments (global ones are NOT included — list them with `null`).
   * `role` accepts one name or a list; `user` and `source` narrow further. Ordered by
   * `(userType, userId, role, source, tenantId)`.
   */
  async listRoleAssignments(filter: RoleAssignmentFilter = {}): Promise<UserRoleAssignment[]> {
    const { roles, userRole } = this.tables;
    const conditions: SQL[] = [];
    if (filter.tenantId !== undefined) {
      conditions.push(eq(userRole.tenantId, filter.tenantId ?? GLOBAL_TENANT));
    }
    const roleNames = roleFilterNames(filter.role);
    if (roleNames !== undefined) {
      if (roleNames.length === 0) return [];
      conditions.push(inArray(roles.name, roleNames));
    }
    if (filter.user !== undefined) {
      const { type, id } = normalizeUserRef(filter.user);
      conditions.push(eq(userRole.userType, type), eq(userRole.userId, id));
    }
    if (filter.source !== undefined) conditions.push(eq(userRole.source, filter.source));
    const rows = await this.db
      .select({
        userType: userRole.userType,
        userId: userRole.userId,
        role: roles.name,
        source: userRole.source,
        tenantId: userRole.tenantId,
      })
      .from(userRole)
      .innerJoin(roles, eq(roles.id, userRole.roleId))
      .where(conditions.length > 0 ? and(...conditions) : undefined);
    return rows
      .map((row) => ({
        userType: row.userType,
        userId: row.userId,
        role: row.role,
        source: row.source,
        tenantId: row.tenantId === GLOBAL_TENANT ? null : row.tenantId,
      }))
      .sort(compareUserRoleAssignments);
  }

  /**
   * The flattened, distinct permission names a user has — the UNION of role-derived permissions
   * (honoring the tenant scope) and DIRECT user permissions (not tenant-scoped). Includes
   * wildcard grants (`posts.*`) verbatim; the core matcher expands them.
   */
  async getPermissionsForUser(user: UserRef, scope?: TenantScope): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const { permissions, rolePermission, userRole, userPermission } = this.tables;
    const [viaRoles, direct] = await Promise.all([
      this.db
        .selectDistinct({ name: permissions.name })
        .from(userRole)
        .innerJoin(rolePermission, eq(rolePermission.roleId, userRole.roleId))
        .innerJoin(permissions, eq(permissions.id, rolePermission.permissionId))
        .where(this.userRoleWhere(type, id, scope)),
      this.db
        .selectDistinct({ name: permissions.name })
        .from(userPermission)
        .innerJoin(permissions, eq(permissions.id, userPermission.permissionId))
        .where(and(eq(userPermission.userType, type), eq(userPermission.userId, id))),
    ]);
    return [...new Set([...viaRoles, ...direct].map((row) => row.name))];
  }

  /** A user's roles + effective permissions in one shot (tenant-aware). */
  async getUserAuthz(user: UserRef, scope?: TenantScope): Promise<UserAuthz> {
    const [roles, permissions] = await Promise.all([
      this.getRolesForUser(user, scope),
      this.getPermissionsForUser(user, scope),
    ]);
    return { roles, permissions };
  }

  /**
   * True when the user holds `permission` (exact name) — via a (tenant-scoped) role OR a direct
   * grant. With no scope, only global role assignments count toward the role path.
   */
  async userHasPermission(
    user: UserRef,
    permission: string,
    scope?: TenantScope,
  ): Promise<boolean> {
    const { type, id } = normalizeUserRef(user);
    const { permissions, rolePermission, userRole, userPermission } = this.tables;
    const viaRole = await this.db
      .select({ x: sql<number>`1` })
      .from(userRole)
      .innerJoin(rolePermission, eq(rolePermission.roleId, userRole.roleId))
      .innerJoin(permissions, eq(permissions.id, rolePermission.permissionId))
      .where(and(this.userRoleWhere(type, id, scope), eq(permissions.name, permission)))
      .limit(1);
    if (viaRole.length > 0) return true;
    const direct = await this.db
      .select({ x: sql<number>`1` })
      .from(userPermission)
      .innerJoin(permissions, eq(permissions.id, userPermission.permissionId))
      .where(
        and(
          eq(userPermission.userType, type),
          eq(userPermission.userId, id),
          eq(permissions.name, permission),
        ),
      )
      .limit(1);
    return direct.length > 0;
  }
}
