export {
  DEFAULT_TABLE_NAMES,
  GLOBAL_TENANT,
  authzSchemaDdl,
  authzTables,
  createAuthzTables,
} from './schema.js';
export type { AuthzTables } from './schema.js';
export { DrizzleAuthzStore } from './drizzle-authz.store.js';
export type { UserAuthz } from './drizzle-authz.store.js';
export {
  AUTHZ_RBAC_OPTIONS,
  AUTHZ_RBAC_STORE,
  AuthzRbacModule,
  defaultUserRefMapper,
} from './authz-rbac.module.js';
export type {
  AuthzRbacModuleAsyncOptions,
  AuthzRbacModuleOptions,
  UserRefMapper,
} from './authz-rbac.module.js';
export type { AuthzStoreOptions, DrizzlePgDatabase, TableNames, TenantScope } from './types.js';
export type { UserRef, UserRefInput } from '@dudousxd/nestjs-authz/store-kit';
export { applyScope, compileScope } from './scope.js';
export type { ScopeColumns, ScopeResolver } from './scope.js';
