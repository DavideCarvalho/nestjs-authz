export {
  AUTHZ_ENTITIES,
  DEFAULT_TABLE_NAMES,
  GLOBAL_TENANT,
  PermissionEntity,
  RoleEntity,
  RolePermissionEntity,
  UserPermissionEntity,
  UserRoleEntity,
} from './entities.js';
export { createAuthzTables, ensureAuthzSchema } from './schema.js';
export { TypeOrmAuthzStore } from './typeorm-authz.store.js';
export type { UserAuthz } from './typeorm-authz.store.js';
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
export type { AuthzStoreOptions, TableNames, TenantScope } from './types.js';
export type { UserRef, UserRefInput } from '@dudousxd/nestjs-authz/store-kit';
export { applyScope, applyScopeConstraint, compileScope } from './scope.js';
export type { CompiledScope, ScopeResolver } from './scope.js';
