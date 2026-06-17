/** BYO table names. Any omitted name falls back to {@link DEFAULT_TABLE_NAMES}. */
export interface TableNames {
  roles?: string;
  permissions?: string;
  rolePermission?: string;
  userRole?: string;
}

/**
 * A reference to a user. Matches nestjs-context's `UserRef` shape (`{ type, id }`),
 * but the store accepts either a full ref or a bare id (defaulting `type` to `'user'`).
 */
export interface UserRefInput {
  type?: string;
  id: string | number;
}

/** A user reference, or just its id (treated as `{ type: 'user', id }`). */
export type UserRef = UserRefInput | string | number;

export interface AuthzStoreOptions {
  /** BYO table names; each defaults to the matching {@link DEFAULT_TABLE_NAMES} entry. */
  tableNames?: TableNames;
  /**
   * Optional Postgres schema (NOT a connection — the connection comes from the app's
   * DI per the persistence contract). Tables are created/queried as `"schema"."table"`.
   */
  schema?: string;
}
