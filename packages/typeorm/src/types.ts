/** BYO table names. Any omitted name falls back to {@link DEFAULT_TABLE_NAMES}. */
export interface TableNames {
  roles?: string;
  permissions?: string;
  rolePermission?: string;
  userRole?: string;
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
