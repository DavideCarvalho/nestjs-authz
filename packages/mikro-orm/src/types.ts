/**
 * Options for the MikroORM RBAC store. Reserved for forward-compatibility — MikroORM
 * derives table names from the registered entities (`@Entity({ tableName })`), so BYO
 * names are configured by re-decorating the entities, not at runtime.
 */
export interface AuthzStoreOptions {}
