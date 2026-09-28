import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import type { AuthzTables } from './schema.js';

/** BYO table names. Any omitted name falls back to {@link DEFAULT_TABLE_NAMES}. */
export interface TableNames {
  roles?: string;
  permissions?: string;
  rolePermission?: string;
  userRole?: string;
  /** Direct user→permission pivot. Defaults to `authz_user_permission`. */
  userPermission?: string;
}

/** Optional tenant scope for a user-role assignment / role-or-permission query. */
export interface TenantScope {
  /**
   * Restrict a role assignment (or a query) to this tenant. Omitted/undefined → the GLOBAL
   * scope (an assignment applies in every tenant; a query sees global assignments only — a
   * tenant-scoped role does NOT leak into an unscoped check).
   */
  tenantId?: string;
}

/**
 * Tenant scope + assignment source for role mutations. `source` (default `'manual'`) records where
 * an assignment came from (`'sso'`, `'scim'`, …) so a sync can replace just its own rows — see
 * `setUserRoles`.
 */
export interface RoleAssignmentScope extends TenantScope {
  source?: string;
}

export interface AuthzStoreOptions {
  /**
   * The Drizzle tables to query — pass the SAME object you spread into your drizzle-kit schema
   * (built with {@link createAuthzTables}). When omitted, the store builds them from
   * `tableNames` / `schema`.
   */
  tables?: AuthzTables;
  /** BYO table names; each defaults to the matching {@link DEFAULT_TABLE_NAMES} entry. Ignored with `tables`. */
  tableNames?: TableNames;
  /** Optional Postgres schema (NOT a connection). Ignored with `tables`. */
  schema?: string;
}

/**
 * Any Drizzle Postgres database or transaction (`drizzle(pool)`, `drizzle(pglite)`, `tx` inside
 * `db.transaction(...)`, ...). The app owns the connection; the store never opens one.
 */
// biome-ignore lint/suspicious/noExplicitAny: the schema generics vary per app; the store only uses the untyped query builder.
export type DrizzlePgDatabase = PgDatabase<PgQueryResultHKT, any, any>;
