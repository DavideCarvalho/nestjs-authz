/** BYO table names. Any omitted name falls back to {@link DEFAULT_TABLE_NAMES}. */
export interface TableNames {
  roles?: string;
  permissions?: string;
  rolePermission?: string;
  userRole?: string;
  /** Direct user→permission pivot (post-v1). Defaults to `authz_user_permission`. */
  userPermission?: string;
}

/** Optional tenant scope for a user-role assignment / role-or-permission query. */
export interface TenantScope {
  /**
   * Restrict a role assignment (or a query) to this tenant. Omitted/undefined →
   * the GLOBAL scope (an assignment applies in every tenant; a query sees global
   * assignments only — a tenant-scoped role does NOT leak into an unscoped check).
   */
  tenantId?: string;
}

export interface AuthzStoreOptions {
  /** BYO table names; each defaults to the matching {@link DEFAULT_TABLE_NAMES} entry. */
  tableNames?: TableNames;
  /**
   * Optional Postgres schema (NOT a connection — the connection comes from the app's
   * DI per the persistence contract). Tables are created/queried as `"schema"."table"`.
   */
  schema?: string;
}
