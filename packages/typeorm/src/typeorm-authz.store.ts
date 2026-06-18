import { randomUUID } from 'node:crypto';
import type { DataSource } from 'typeorm';
import { DEFAULT_TABLE_NAMES, GLOBAL_TENANT } from './entities.js';
import { ensureAuthzSchema } from './schema.js';
import { Placeholders, assertSafeIdentifier } from './sql.js';
import type { AuthzStoreOptions, TenantScope, UserRef } from './types.js';

/** Normalize a {@link UserRef} to `{ type, id }` with `id` stringified. */
function normalizeUserRef(ref: UserRef): { type: string; id: string } {
  if (typeof ref === 'string' || typeof ref === 'number') {
    return { type: 'user', id: String(ref) };
  }
  return { type: ref.type ?? 'user', id: String(ref.id) };
}

/**
 * A user's effective permissions: the role names they hold and the flattened set of
 * permission names granted by those roles.
 */
export interface UserAuthz {
  roles: string[];
  permissions: string[];
}

/**
 * TypeORM-backed RBAC store. A plain POJO that receives the `DataSource` in its
 * constructor — NOT `@Injectable`, no internal connection token (the app owns the
 * connection and plugs it via DI; see the persistence contract).
 *
 * BYO table names + an optional Postgres schema flow from {@link AuthzStoreOptions};
 * the store qualifies every table reference accordingly so it never assumes a name.
 */
export class TypeOrmAuthzStore {
  private readonly names: Record<
    'roles' | 'permissions' | 'rolePermission' | 'userRole' | 'userPermission',
    string
  >;
  private readonly schema: string | undefined;

  constructor(
    private readonly dataSource: DataSource,
    private readonly opts: AuthzStoreOptions = {},
  ) {
    this.names = {
      roles: opts.tableNames?.roles ?? DEFAULT_TABLE_NAMES.roles,
      permissions: opts.tableNames?.permissions ?? DEFAULT_TABLE_NAMES.permissions,
      rolePermission: opts.tableNames?.rolePermission ?? DEFAULT_TABLE_NAMES.rolePermission,
      userRole: opts.tableNames?.userRole ?? DEFAULT_TABLE_NAMES.userRole,
      userPermission: opts.tableNames?.userPermission ?? DEFAULT_TABLE_NAMES.userPermission,
    };
    this.schema = opts.schema;

    // P4: identifiers are interpolated into SQL — validate BYO names/schema up
    // front so a hostile value (e.g. one with a `"`) can never reach a query.
    for (const [key, name] of Object.entries(this.names)) {
      assertSafeIdentifier(name, `table name (${key})`);
    }
    if (this.schema !== undefined) {
      assertSafeIdentifier(this.schema, 'schema name');
    }
  }

  /** Create/upgrade the RBAC tables (delegates to {@link ensureAuthzSchema}). */
  ensureSchema(): Promise<void> {
    return ensureAuthzSchema(this.dataSource, this.opts);
  }

  /** A fresh, dialect-correct positional-placeholder generator for one query. */
  private params(): Placeholders {
    return Placeholders.for(this.dataSource);
  }

  /** Schema-qualified, driver-escaped table reference. */
  private table(key: keyof typeof this.names): string {
    const quote = (id: string) => this.dataSource.driver.escape(id);
    const name = quote(this.names[key]);
    return this.schema ? `${quote(this.schema)}.${name}` : name;
  }

  private col(id: string): string {
    return this.dataSource.driver.escape(id);
  }

  // --- roles & permissions (idempotent upserts by name) ---

  /** Dialect-correct `INSERT ... <conflict-ignore>` clause for a unique-key upsert. */
  private insertIgnoreSuffix(): string {
    // Postgres/SQLite speak `ON CONFLICT DO NOTHING`; MySQL/MariaDB use `INSERT IGNORE`
    // (handled at the verb in `insertIgnoreVerb`). Returning a trailing clause keeps
    // the call sites uniform.
    const type = this.dataSource.options.type;
    if (type === 'mysql' || type === 'mariadb' || type === 'aurora-mysql') return '';
    return ' ON CONFLICT DO NOTHING';
  }

  /** Dialect-correct INSERT verb (`INSERT` vs MySQL's `INSERT IGNORE`). */
  private insertIgnoreVerb(): string {
    const type = this.dataSource.options.type;
    if (type === 'mysql' || type === 'mariadb' || type === 'aurora-mysql') return 'INSERT IGNORE';
    return 'INSERT';
  }

  /**
   * Create the role if absent; returns its id. Idempotent and race-tolerant: the
   * INSERT is dialect-aware conflict-ignoring (`ON CONFLICT DO NOTHING` /
   * `INSERT IGNORE`) on the unique `name`, and the id is re-read afterwards so two
   * concurrent creators converge on the same row.
   */
  async createRole(name: string): Promise<string> {
    const existing = await this.findRoleId(name);
    if (existing) return existing;
    const p = this.params();
    await this.dataSource.query(
      `${this.insertIgnoreVerb()} INTO ${this.table('roles')} (${this.col('id')}, ${this.col(
        'name',
      )}, ${this.col('guard')}, ${this.col('createdAt')}) VALUES (${p.next()}, ${p.next()}, NULL, ${p.next()})${this.insertIgnoreSuffix()}`,
      [randomUUID(), name, new Date().toISOString()],
    );
    // Re-read: handles a concurrent insert that won the race (ours was ignored).
    const id = await this.findRoleId(name);
    if (!id) throw new Error(`Failed to create or resolve role "${name}".`);
    return id;
  }

  /** Create the permission if absent; returns its id. Idempotent and race-tolerant. */
  async createPermission(name: string): Promise<string> {
    const existing = await this.findPermissionId(name);
    if (existing) return existing;
    const p = this.params();
    await this.dataSource.query(
      `${this.insertIgnoreVerb()} INTO ${this.table('permissions')} (${this.col(
        'id',
      )}, ${this.col('name')}, ${this.col('guard')}, ${this.col('createdAt')}) VALUES (${p.next()}, ${p.next()}, NULL, ${p.next()})${this.insertIgnoreSuffix()}`,
      [randomUUID(), name, new Date().toISOString()],
    );
    const id = await this.findPermissionId(name);
    if (!id) throw new Error(`Failed to create or resolve permission "${name}".`);
    return id;
  }

  private async findRoleId(name: string): Promise<string | undefined> {
    const p = this.params();
    const rows = (await this.dataSource.query(
      `SELECT ${this.col('id')} AS id FROM ${this.table('roles')} WHERE ${this.col(
        'name',
      )} = ${p.next()}`,
      [name],
    )) as Array<{ id: string }>;
    return rows[0]?.id;
  }

  private async findPermissionId(name: string): Promise<string | undefined> {
    const p = this.params();
    const rows = (await this.dataSource.query(
      `SELECT ${this.col('id')} AS id FROM ${this.table('permissions')} WHERE ${this.col(
        'name',
      )} = ${p.next()}`,
      [name],
    )) as Array<{ id: string }>;
    return rows[0]?.id;
  }

  // --- role ↔ permission ---

  /** Grant a permission to a role (creating both by name if needed). Idempotent. */
  async givePermissionToRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.createRole(roleName);
    const permissionId = await this.createPermission(permissionName);
    const p = this.params();
    await this.dataSource.query(
      `${this.insertIgnoreVerb()} INTO ${this.table('rolePermission')} (${this.col(
        'roleId',
      )}, ${this.col('permissionId')}) VALUES (${p.next()}, ${p.next()})${this.insertIgnoreSuffix()}`,
      [roleId, permissionId],
    );
  }

  /** Revoke a permission from a role. No-op if either is absent or not linked. */
  async revokePermissionFromRole(roleName: string, permissionName: string): Promise<void> {
    const roleId = await this.findRoleId(roleName);
    const permissionId = await this.findPermissionId(permissionName);
    if (!roleId || !permissionId) return;
    const p = this.params();
    await this.dataSource.query(
      `DELETE FROM ${this.table('rolePermission')} WHERE ${this.col(
        'roleId',
      )} = ${p.next()} AND ${this.col('permissionId')} = ${p.next()}`,
      [roleId, permissionId],
    );
  }

  // --- user ↔ role ---

  /**
   * Assign a role to a user (creating the role by name if needed). Idempotent.
   *
   * Pass `{ tenantId }` to scope the assignment to a tenant — it then applies ONLY
   * within that tenant. Omitting it (the default) makes a GLOBAL assignment that
   * applies in every tenant (and in an unscoped check). The same `(user, role)` can
   * be assigned in multiple tenants independently.
   */
  async assignRole(user: UserRef, roleName: string, scope?: TenantScope): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.createRole(roleName);
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    const p = this.params();
    await this.dataSource.query(
      `${this.insertIgnoreVerb()} INTO ${this.table('userRole')} (${this.col(
        'userType',
      )}, ${this.col('userId')}, ${this.col('roleId')}, ${this.col('tenantId')}) VALUES (${p.next()}, ${p.next()}, ${p.next()}, ${p.next()})${this.insertIgnoreSuffix()}`,
      [type, id, roleId, tenantId],
    );
  }

  /**
   * Remove a role from a user. No-op if the role or assignment is absent. When
   * `{ tenantId }` is given, only the assignment in THAT tenant is removed; omitting
   * it removes the GLOBAL assignment (tenant `''`).
   */
  async removeRole(user: UserRef, roleName: string, scope?: TenantScope): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    const p = this.params();
    await this.dataSource.query(
      `DELETE FROM ${this.table('userRole')} WHERE ${this.col('userType')} = ${p.next()} AND ${this.col(
        'userId',
      )} = ${p.next()} AND ${this.col('roleId')} = ${p.next()} AND ${this.col('tenantId')} = ${p.next()}`,
      [type, id, roleId, tenantId],
    );
  }

  // --- user ↔ permission (DIRECT grant, no role) ---

  /**
   * Grant a permission DIRECTLY to a user (creating the permission by name if
   * needed) — no role required. Mirrors Laravel/spatie's `$user->givePermissionTo`.
   * Idempotent.
   */
  async giveUserPermission(user: UserRef, permissionName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const permissionId = await this.createPermission(permissionName);
    const p = this.params();
    await this.dataSource.query(
      `${this.insertIgnoreVerb()} INTO ${this.table('userPermission')} (${this.col(
        'userType',
      )}, ${this.col('userId')}, ${this.col('permissionId')}) VALUES (${p.next()}, ${p.next()}, ${p.next()})${this.insertIgnoreSuffix()}`,
      [type, id, permissionId],
    );
  }

  /**
   * Revoke a DIRECT user permission. No-op if the permission or grant is absent.
   * Only the direct grant is removed — a permission the user ALSO has via a role
   * survives.
   */
  async revokeUserPermission(user: UserRef, permissionName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const permissionId = await this.findPermissionId(permissionName);
    if (!permissionId) return;
    const p = this.params();
    await this.dataSource.query(
      `DELETE FROM ${this.table('userPermission')} WHERE ${this.col('userType')} = ${p.next()} AND ${this.col(
        'userId',
      )} = ${p.next()} AND ${this.col('permissionId')} = ${p.next()}`,
      [type, id, permissionId],
    );
  }

  // --- queries ---

  /**
   * SQL fragment + params matching role assignments visible for a tenant scope: a
   * GLOBAL assignment (tenant `''`) always applies; a tenant-scoped one applies only
   * when its tenant matches the requested one. With no requested tenant, only global
   * assignments are visible (a tenant-scoped role never leaks into an unscoped check).
   */
  private tenantFilter(alias: string, scope: TenantScope | undefined, p: Placeholders): string {
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    if (tenantId === GLOBAL_TENANT) {
      return ` AND ${alias}.${this.col('tenantId')} = ${p.next()}`;
    }
    // Visible = global OR exactly this tenant.
    return ` AND (${alias}.${this.col('tenantId')} = ${p.next()} OR ${alias}.${this.col(
      'tenantId',
    )} = ${p.next()})`;
  }

  /** Bind values for {@link tenantFilter}, in the same order it emits placeholders. */
  private tenantParams(scope: TenantScope | undefined): string[] {
    const tenantId = scope?.tenantId ?? GLOBAL_TENANT;
    return tenantId === GLOBAL_TENANT ? [GLOBAL_TENANT] : [GLOBAL_TENANT, tenantId];
  }

  /**
   * The role names a user holds, optionally restricted to a tenant scope (see
   * {@link assignRole}). With no scope, only global roles are returned.
   */
  async getRolesForUser(user: UserRef, scope?: TenantScope): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const p = this.params();
    const userType = p.next();
    const userId = p.next();
    const filter = this.tenantFilter('ur', scope, p);
    const rows = (await this.dataSource.query(
      `SELECT r.${this.col('name')} AS name
       FROM ${this.table('userRole')} ur
       JOIN ${this.table('roles')} r ON r.${this.col('id')} = ur.${this.col('roleId')}
       WHERE ur.${this.col('userType')} = ${userType} AND ur.${this.col('userId')} = ${userId}${filter}`,
      [type, id, ...this.tenantParams(scope)],
    )) as Array<{ name: string }>;
    return rows.map((row) => row.name);
  }

  /**
   * The flattened, distinct permission names a user has — the UNION of role-derived
   * permissions (honoring the tenant scope) and DIRECT user permissions (which are
   * not tenant-scoped). With no scope, role-derived permissions come from global
   * roles only.
   */
  async getPermissionsForUser(user: UserRef, scope?: TenantScope): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);

    // Role-derived (tenant-aware).
    const pr = this.params();
    const rUserType = pr.next();
    const rUserId = pr.next();
    const rFilter = this.tenantFilter('ur', scope, pr);
    const roleRows = (await this.dataSource.query(
      `SELECT DISTINCT p.${this.col('name')} AS name
       FROM ${this.table('userRole')} ur
       JOIN ${this.table('rolePermission')} rp ON rp.${this.col('roleId')} = ur.${this.col(
         'roleId',
       )}
       JOIN ${this.table('permissions')} p ON p.${this.col('id')} = rp.${this.col('permissionId')}
       WHERE ur.${this.col('userType')} = ${rUserType} AND ur.${this.col(
         'userId',
       )} = ${rUserId}${rFilter}`,
      [type, id, ...this.tenantParams(scope)],
    )) as Array<{ name: string }>;

    // Direct grants (not tenant-scoped).
    const pd = this.params();
    const directRows = (await this.dataSource.query(
      `SELECT DISTINCT p.${this.col('name')} AS name
       FROM ${this.table('userPermission')} up
       JOIN ${this.table('permissions')} p ON p.${this.col('id')} = up.${this.col('permissionId')}
       WHERE up.${this.col('userType')} = ${pd.next()} AND up.${this.col('userId')} = ${pd.next()}`,
      [type, id],
    )) as Array<{ name: string }>;

    const out = new Set<string>();
    for (const row of roleRows) out.add(row.name);
    for (const row of directRows) out.add(row.name);
    return [...out];
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
   * True when the user holds `permission` — via a (tenant-scoped) role OR a direct
   * grant. With no scope, only global role assignments count toward the role path;
   * direct grants always count.
   */
  async userHasPermission(
    user: UserRef,
    permission: string,
    scope?: TenantScope,
  ): Promise<boolean> {
    const { type, id } = normalizeUserRef(user);

    // Role path (tenant-aware).
    const pr = this.params();
    const rUserType = pr.next();
    const rUserId = pr.next();
    const rName = pr.next();
    const rFilter = this.tenantFilter('ur', scope, pr);
    const roleRows = (await this.dataSource.query(
      `SELECT 1 AS x
       FROM ${this.table('userRole')} ur
       JOIN ${this.table('rolePermission')} rp ON rp.${this.col('roleId')} = ur.${this.col(
         'roleId',
       )}
       JOIN ${this.table('permissions')} p ON p.${this.col('id')} = rp.${this.col('permissionId')}
       WHERE ur.${this.col('userType')} = ${rUserType} AND ur.${this.col(
         'userId',
       )} = ${rUserId} AND p.${this.col('name')} = ${rName}${rFilter}
       LIMIT 1`,
      [type, id, permission, ...this.tenantParams(scope)],
    )) as unknown[];
    if (roleRows.length > 0) return true;

    // Direct path.
    const pd = this.params();
    const directRows = (await this.dataSource.query(
      `SELECT 1 AS x
       FROM ${this.table('userPermission')} up
       JOIN ${this.table('permissions')} p ON p.${this.col('id')} = up.${this.col('permissionId')}
       WHERE up.${this.col('userType')} = ${pd.next()} AND up.${this.col(
         'userId',
       )} = ${pd.next()} AND p.${this.col('name')} = ${pd.next()}
       LIMIT 1`,
      [type, id, permission],
    )) as unknown[];
    return directRows.length > 0;
  }
}
