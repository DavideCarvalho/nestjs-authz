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
import type { EntityManager, MikroORM } from '@mikro-orm/core';
import {
  GLOBAL_TENANT,
  PermissionEntity,
  RoleEntity,
  RolePermissionEntity,
  UserRoleEntity,
} from './entities.js';
import { ensureAuthzSchema } from './schema.js';

// These types appear in this store's public method signatures, so the package exports them
// next to the store. They are defined once in core's store-kit.
export type { RoleAssignment, RoleAssignmentFilter, UserAuthz, UserRoleAssignment };

/**
 * Optional tenant scope for a query. Omitted → the GLOBAL scope (only global assignments; a
 * tenant-scoped role never leaks into an unscoped check). With a `tenantId`, global assignments
 * AND that tenant's apply. Needs entities built with `tenantScoped: true`; without that column
 * every assignment is global.
 */
export interface TenantScope {
  tenantId?: string;
}

/**
 * Assignment source (default `'manual'`, see `setUserRoles`) and tenant for role mutations.
 * `tenantId` scopes the assignment to one tenant; it needs entities built with
 * `createAuthzEntitySchemas(names, { tenantScoped: true })`.
 */
export interface RoleSourceOptions extends TenantScope {
  source?: string;
}

const TENANT_COLUMN_MISSING =
  'MikroOrmAuthzStore: a tenant-scoped role assignment needs the tenantId column. Build the ' +
  'entities with createAuthzEntitySchemas(names, { tenantScoped: true }) and widen the ' +
  "user-role primary key (see the package README, 'Tenant-scoped roles').";

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

  // --- tenant scoping ---

  /** True when the user-role entity maps `tenantId` (built with `tenantScoped: true`). */
  private tenantScoped(em: EntityManager): boolean {
    return em.getMetadata().find(UserRoleEntity.name)?.properties.tenantId !== undefined;
  }

  /** The `tenantId` value of a written assignment (`{}` without the column). */
  private tenantValue(em: EntityManager, tenantId: string | undefined): { tenantId?: string } {
    if (this.tenantScoped(em)) return { tenantId: tenantId ?? GLOBAL_TENANT };
    if (tenantId !== undefined && tenantId !== GLOBAL_TENANT) {
      throw new Error(TENANT_COLUMN_MISSING);
    }
    return {};
  }

  /** Assignments visible in a scope: global ones, plus the tenant's own when one is given. */
  private tenantWhere(em: EntityManager, scope: TenantScope | undefined): Record<string, unknown> {
    if (!this.tenantScoped(em)) return {};
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    return tenantId === GLOBAL_TENANT
      ? { tenantId: GLOBAL_TENANT }
      : { tenantId: { $in: [GLOBAL_TENANT, tenantId] } };
  }

  /** The public `tenantId` of a stored row: `null` for a global assignment. */
  private static rowTenant(row: UserRoleEntity & { tenantId?: string }): string | null {
    return row.tenantId === undefined || row.tenantId === GLOBAL_TENANT ? null : row.tenantId;
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

  /**
   * Delete a role together with its role→permission links and EVERY user assignment of it (all
   * sources), in one transaction. Returns whether the role existed. The permissions themselves
   * are kept (other roles may use them).
   */
  async deleteRole(roleName: string): Promise<boolean> {
    return this.em.fork().transactional(async (tx) => {
      const role = await tx.findOne(RoleEntity, { name: roleName });
      if (!role) return false;
      await tx.nativeDelete(UserRoleEntity, { roleId: role.id });
      await tx.nativeDelete(RolePermissionEntity, { roleId: role.id });
      await tx.nativeDelete(RoleEntity, { id: role.id });
      return true;
    });
  }

  /**
   * REPLACE the role's permission set with exactly `permissionNames` (spatie's
   * `syncPermissions`): links not in the list are removed, missing ones added. The role and the
   * permissions are created by name when missing (idempotently, before the swap); the delete +
   * re-insert of the links is transactional. An empty list leaves the role with no permissions.
   */
  async syncRolePermissions(roleName: string, permissionNames: readonly string[]): Promise<void> {
    const roleId = await this.createRole(roleName);
    const permissionIds: string[] = [];
    for (const name of new Set(permissionNames)) {
      permissionIds.push(await this.createPermission(name));
    }
    await this.em.fork().transactional(async (tx) => {
      await tx.nativeDelete(RolePermissionEntity, { roleId });
      for (const permissionId of permissionIds) {
        tx.create(RolePermissionEntity, { roleId, permissionId });
      }
      await tx.flush();
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
    const em = this.em.fork();
    const meta = em.getMetadata();
    const role = meta.get(RoleEntity.name);
    const perm = meta.get(PermissionEntity.name);
    const rolePerm = meta.get(RolePermissionEntity.name);
    const col = (m: typeof role, prop: string): string => {
      const field = m.properties[prop]?.fieldNames?.[0];
      if (!field) throw new Error(`Missing column metadata for ${m.className}.${prop}`);
      return field;
    };
    // Identifiers come from entity metadata (trusted); role names are bound parameters.
    const sql =
      `select r.${col(role, 'name')} as role, p.${col(perm, 'name')} as permission ` +
      `from ${role.tableName} r ` +
      `left join ${rolePerm.tableName} rp on rp.${col(rolePerm, 'roleId')} = r.${col(role, 'id')} ` +
      `left join ${perm.tableName} p on p.${col(perm, 'id')} = rp.${col(rolePerm, 'permissionId')} ` +
      `where r.${col(role, 'name')} in (${names.map(() => '?').join(', ')})`;
    const rows = (await em.getConnection().execute(sql, names)) as Array<{
      role: string;
      permission: string | null;
    }>;
    for (const row of rows) {
      let list = out[row.role];
      if (!list) {
        list = [];
        out[row.role] = list;
      }
      if (row.permission !== null && row.permission !== undefined) list.push(row.permission);
    }
    for (const list of Object.values(out)) list.sort();
    return out;
  }

  // --- user ↔ role ---

  /**
   * Assign a role to a user (creating the role by name if needed). Idempotent. `{ source }`
   * (default `'manual'`) records where the assignment came from. `{ tenantId }` scopes it to that
   * tenant; omitted, the assignment is global (applies in every tenant).
   */
  async assignRole(user: UserRef, roleName: string, opts?: RoleSourceOptions): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const tenant = this.tenantValue(em, opts?.tenantId);
    const roleId = await this.createRole(roleName);
    const source = opts?.source ?? DEFAULT_ROLE_SOURCE;
    const existing = await em.findOne(UserRoleEntity, {
      userType: type,
      userId: id,
      roleId,
      source,
      ...tenant,
    });
    if (existing) return;
    em.create(UserRoleEntity, { userType: type, userId: id, roleId, source, ...tenant });
    await em.flush();
  }

  /**
   * Remove a role from a user. No-op if the role or assignment is absent. With `{ source }` only
   * that source's assignment goes; without it, the role is removed from every source. With
   * tenant-scoped entities, `{ tenantId }` removes the assignment in that tenant and omitting it
   * removes the global one.
   */
  async removeRole(user: UserRef, roleName: string, opts?: RoleSourceOptions): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    if (!this.tenantScoped(em) && opts?.tenantId !== undefined && opts.tenantId !== GLOBAL_TENANT) {
      return; // no tenant column: there is no tenant-scoped assignment to remove
    }
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    await em.nativeDelete(UserRoleEntity, {
      userType: type,
      userId: id,
      roleId,
      ...this.tenantValue(em, opts?.tenantId),
      ...(opts?.source !== undefined ? { source: opts.source } : {}),
    });
  }

  /**
   * REPLACE the user's role assignments of ONE source (default `'manual'`) with exactly
   * `roleNames` — e.g. an SSO/SCIM sync calls `setUserRoles(user, mappedRoles, { source: 'sso' })`
   * on every login. Other sources' assignments are untouched, so a role held both manually and via
   * SSO survives an SSO sync that drops it. Roles are created by name when missing. Transactional.
   * With tenant-scoped entities it replaces the assignments of one tenant (`{ tenantId }`), or the
   * global ones when omitted.
   */
  async setUserRoles(
    user: UserRef,
    roleNames: readonly string[],
    opts?: RoleSourceOptions,
  ): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const source = opts?.source ?? DEFAULT_ROLE_SOURCE;
    const em = this.em.fork();
    const tenant = this.tenantValue(em, opts?.tenantId);
    const roleIds: string[] = [];
    for (const name of new Set(roleNames)) roleIds.push(await this.createRole(name));
    await em.transactional(async (tx) => {
      await tx.nativeDelete(UserRoleEntity, { userType: type, userId: id, source, ...tenant });
      for (const roleId of roleIds) {
        tx.create(UserRoleEntity, { userType: type, userId: id, roleId, source, ...tenant });
      }
      await tx.flush();
    });
  }

  /**
   * Every role assignment of a user visible in a tenant scope (global ones always; the tenant's
   * own with `{ tenantId }`), one entry per `(role, source, tenant)`.
   */
  async getRoleAssignments(user: UserRef, scope?: TenantScope): Promise<RoleAssignment[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const assignments = await em.find(UserRoleEntity, {
      userType: type,
      userId: id,
      ...this.tenantWhere(em, scope),
    });
    if (assignments.length === 0) return [];
    const roles = await em.find(RoleEntity, { id: { $in: assignments.map((a) => a.roleId) } });
    const nameById = new Map(roles.map((r) => [r.id, r.name]));
    return assignments
      .filter((a) => nameById.has(a.roleId))
      .map((a) => ({
        role: nameById.get(a.roleId) as string,
        source: a.source,
        tenantId: MikroOrmAuthzStore.rowTenant(a),
      }))
      .sort(
        (a, b) =>
          a.role.localeCompare(b.role) ||
          a.source.localeCompare(b.source) ||
          (a.tenantId ?? '').localeCompare(b.tenantId ?? ''),
      );
  }

  /**
   * Raw role-assignment rows for admin listings — e.g. who holds a role (`{ role: 'admin' }`) or
   * a user's assignments with their sources (`{ user }`). `role` accepts one name or a list;
   * `user` and `source` narrow further. Ordered by `(userType, userId, role, source)`.
   *
   * `tenantId`: omitted = no tenant filter; `null` = global assignments only; a string = exactly
   * that tenant's scoped assignments. Without tenant-scoped entities every row is global
   * (`tenantId: null`), so a tenant id string matches nothing.
   */
  async listRoleAssignments(filter: RoleAssignmentFilter = {}): Promise<UserRoleAssignment[]> {
    const em = this.em.fork();
    const where: Record<string, unknown> = {};
    if (filter.tenantId !== undefined) {
      if (this.tenantScoped(em)) where.tenantId = filter.tenantId ?? GLOBAL_TENANT;
      else if (filter.tenantId !== null) return [];
    }
    const roleNames = roleFilterNames(filter.role);
    if (roleNames !== undefined) {
      if (roleNames.length === 0) return [];
      const roles = await em.find(RoleEntity, { name: { $in: roleNames } });
      if (roles.length === 0) return [];
      where.roleId = { $in: roles.map((r) => r.id) };
    }
    if (filter.user !== undefined) {
      const { type, id } = normalizeUserRef(filter.user);
      where.userType = type;
      where.userId = id;
    }
    if (filter.source !== undefined) where.source = filter.source;
    const assignments = await em.find(UserRoleEntity, where);
    if (assignments.length === 0) return [];
    const roles = await em.find(RoleEntity, {
      id: { $in: [...new Set(assignments.map((a) => a.roleId))] },
    });
    const nameById = new Map(roles.map((r) => [r.id, r.name]));
    return assignments
      .filter((a) => nameById.has(a.roleId))
      .map((a) => ({
        userType: a.userType,
        userId: a.userId,
        role: nameById.get(a.roleId) as string,
        source: a.source,
        tenantId: MikroOrmAuthzStore.rowTenant(a),
      }))
      .sort(compareUserRoleAssignments);
  }

  /**
   * Delete every role assignment of the user (all sources) — e.g. when the account is deleted.
   * Roles and permissions are kept. (This adapter has no direct user permissions.)
   */
  async removeUser(user: UserRef): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    await this.em.fork().nativeDelete(UserRoleEntity, { userType: type, userId: id });
  }

  // --- queries ---

  /** The role names a user holds, in a tenant scope (see {@link TenantScope}). */
  async getRolesForUser(user: UserRef, scope?: TenantScope): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const em = this.em.fork();
    const assignments = await em.find(UserRoleEntity, {
      userType: type,
      userId: id,
      ...this.tenantWhere(em, scope),
    });
    if (assignments.length === 0) return [];
    const roleIds = [...new Set(assignments.map((a) => a.roleId))];
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
  async getPermissionsForUser(user: UserRef, scope?: TenantScope): Promise<string[]> {
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

    // Tenant scope: global assignments, plus the tenant's own when one is given.
    const params: string[] = [type, id];
    let tenantSql = '';
    if (this.tenantScoped(em)) {
      const urTenant = col(userRole, 'tenantId');
      const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
      if (tenantId === GLOBAL_TENANT) {
        tenantSql = ` and ur.${urTenant} = ?`;
        params.push(GLOBAL_TENANT);
      } else {
        tenantSql = ` and ur.${urTenant} in (?, ?)`;
        params.push(GLOBAL_TENANT, tenantId);
      }
    }

    // Single round-trip: permission ← rolePermission ← userRole. Identifiers come from
    // entity metadata (trusted), values are bound as parameters (no SQL injection surface).
    const sql =
      `select distinct p.${permName} as name ` +
      `from ${permTable} p ` +
      `inner join ${rpTable} rp on rp.${rpPermId} = p.${permId} ` +
      `inner join ${urTable} ur on ur.${urRoleId} = rp.${rpRoleId} ` +
      `where ur.${urUserType} = ? and ur.${urUserId} = ?${tenantSql}`;

    const rows = (await em.getConnection().execute(sql, params)) as Array<{ name: string }>;
    return [...new Set(rows.map((r) => r.name))];
  }

  /** A user's roles + effective permissions in one shot, in a tenant scope. */
  async getUserAuthz(user: UserRef, scope?: TenantScope): Promise<UserAuthz> {
    const [roles, permissions] = await Promise.all([
      this.getRolesForUser(user, scope),
      this.getPermissionsForUser(user, scope),
    ]);
    return { roles, permissions };
  }

  /** True when the user holds `permission` through any of their roles, in a tenant scope. */
  async userHasPermission(
    user: UserRef,
    permission: string,
    scope?: TenantScope,
  ): Promise<boolean> {
    const permissions = await this.getPermissionsForUser(user, scope);
    return permissions.includes(permission);
  }
}
