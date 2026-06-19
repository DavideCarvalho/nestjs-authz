import { randomUUID } from 'node:crypto';
import { type UserAuthz, type UserRef, normalizeUserRef } from '@dudousxd/nestjs-authz/store-kit';
import type { DataSource } from 'typeorm';
import { DEFAULT_TABLE_NAMES } from './entities.js';
import { ensureAuthzSchema } from './schema.js';
import { Placeholders, assertSafeIdentifier } from './sql.js';
import type { AuthzStoreOptions } from './types.js';

// Re-exported so `@dudousxd/nestjs-authz-typeorm`'s public `UserAuthz` keeps the
// same import path; canonical definition lives in core's store-kit.
export type { UserAuthz };

/**
 * TypeORM-backed RBAC store. A plain POJO that receives the `DataSource` in its
 * constructor — NOT `@Injectable`, no internal connection token (the app owns the
 * connection and plugs it via DI; see the persistence contract).
 *
 * BYO table names + an optional Postgres schema flow from {@link AuthzStoreOptions};
 * the store qualifies every table reference accordingly so it never assumes a name.
 */
export class TypeOrmAuthzStore {
  private readonly names: Record<'roles' | 'permissions' | 'rolePermission' | 'userRole', string>;
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

  /** Assign a role to a user (creating the role by name if needed). Idempotent. */
  async assignRole(user: UserRef, roleName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.createRole(roleName);
    const p = this.params();
    await this.dataSource.query(
      `${this.insertIgnoreVerb()} INTO ${this.table('userRole')} (${this.col(
        'userType',
      )}, ${this.col('userId')}, ${this.col('roleId')}) VALUES (${p.next()}, ${p.next()}, ${p.next()})${this.insertIgnoreSuffix()}`,
      [type, id, roleId],
    );
  }

  /** Remove a role from a user. No-op if the role or assignment is absent. */
  async removeRole(user: UserRef, roleName: string): Promise<void> {
    const { type, id } = normalizeUserRef(user);
    const roleId = await this.findRoleId(roleName);
    if (!roleId) return;
    const p = this.params();
    await this.dataSource.query(
      `DELETE FROM ${this.table('userRole')} WHERE ${this.col('userType')} = ${p.next()} AND ${this.col(
        'userId',
      )} = ${p.next()} AND ${this.col('roleId')} = ${p.next()}`,
      [type, id, roleId],
    );
  }

  // --- queries ---

  /** The role names a user holds. */
  async getRolesForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const p = this.params();
    const rows = (await this.dataSource.query(
      `SELECT r.${this.col('name')} AS name
       FROM ${this.table('userRole')} ur
       JOIN ${this.table('roles')} r ON r.${this.col('id')} = ur.${this.col('roleId')}
       WHERE ur.${this.col('userType')} = ${p.next()} AND ur.${this.col('userId')} = ${p.next()}`,
      [type, id],
    )) as Array<{ name: string }>;
    return rows.map((row) => row.name);
  }

  /** The flattened, distinct permission names a user has via their roles. */
  async getPermissionsForUser(user: UserRef): Promise<string[]> {
    const { type, id } = normalizeUserRef(user);
    const p = this.params();
    const rows = (await this.dataSource.query(
      `SELECT DISTINCT p.${this.col('name')} AS name
       FROM ${this.table('userRole')} ur
       JOIN ${this.table('rolePermission')} rp ON rp.${this.col('roleId')} = ur.${this.col(
         'roleId',
       )}
       JOIN ${this.table('permissions')} p ON p.${this.col('id')} = rp.${this.col('permissionId')}
       WHERE ur.${this.col('userType')} = ${p.next()} AND ur.${this.col('userId')} = ${p.next()}`,
      [type, id],
    )) as Array<{ name: string }>;
    return rows.map((row) => row.name);
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
    const { type, id } = normalizeUserRef(user);
    const p = this.params();
    const rows = (await this.dataSource.query(
      `SELECT 1 AS x
       FROM ${this.table('userRole')} ur
       JOIN ${this.table('rolePermission')} rp ON rp.${this.col('roleId')} = ur.${this.col(
         'roleId',
       )}
       JOIN ${this.table('permissions')} p ON p.${this.col('id')} = rp.${this.col('permissionId')}
       WHERE ur.${this.col('userType')} = ${p.next()} AND ur.${this.col(
         'userId',
       )} = ${p.next()} AND p.${this.col('name')} = ${p.next()}
       LIMIT 1`,
      [type, id, permission],
    )) as unknown[];
    return rows.length > 0;
  }
}
