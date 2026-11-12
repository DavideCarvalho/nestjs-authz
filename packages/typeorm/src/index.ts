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
export type {
  RoleAssignment,
  RoleAssignmentFilter,
  UserAuthz,
  UserRoleAssignment,
} from './typeorm-authz.store.js';
export {
  AUTHZ_RBAC_OPTIONS,
  AUTHZ_RBAC_STORE,
  AuthzRbacModule,
  defaultUserRefMapper,
} from './authz-rbac.module.js';
export type {
  AuthzRbacModuleAsyncOptions,
  AuthzRbacModuleBaseOptions,
  AuthzRbacModuleOptions,
  UserRefMapper,
} from './authz-rbac.module.js';
export type { AuthzStoreOptions, RoleAssignmentScope, TableNames, TenantScope } from './types.js';
export type { AuthzTenancyOption, TenantResolver } from './tenancy.js';
export type { UserRef, UserRefInput } from '@dudousxd/nestjs-authz/store-kit';
export { applyScope, applyScopeConstraint, compileScope } from './scope.js';
export type { CompiledScope, ScopeResolver } from './scope.js';
