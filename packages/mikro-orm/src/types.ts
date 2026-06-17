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

/**
 * Options for the MikroORM RBAC store. Reserved for forward-compatibility — MikroORM
 * derives table names from the registered entities (`@Entity({ tableName })`), so BYO
 * names are configured by re-decorating the entities, not at runtime.
 */
export interface AuthzStoreOptions {}
