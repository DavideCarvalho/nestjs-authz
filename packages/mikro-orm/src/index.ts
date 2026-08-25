export {
  AUTHZ_ENTITIES,
  AUTHZ_ENTITY_CLASSES,
  createAuthzEntitySchemas,
  DEFAULT_TABLE_NAMES,
  PermissionEntity,
  PermissionEntitySchema,
  RoleEntity,
  RoleEntitySchema,
  RolePermissionEntity,
  RolePermissionEntitySchema,
  UserRoleEntity,
  UserRoleEntitySchema,
} from './entities.js';
export type { AuthzEntitySchemas, AuthzTableNames } from './entities.js';
// VALUE exports on purpose: these classes are the DI tokens `MikroOrmModule.forFeature()`
// registers, so `export type` would compile green and be `undefined` at runtime.
export {
  AuthzPermissionRepository,
  AuthzRolePermissionRepository,
  AuthzRoleRepository,
  AuthzUserRoleRepository,
} from './repositories.js';
export { authzSchemaSql, ensureAuthzSchema } from './schema.js';
export { MikroOrmAuthzStore } from './mikro-orm-authz.store.js';
export type { UserAuthz } from './mikro-orm-authz.store.js';
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
export type { AuthzStoreOptions } from './types.js';
export type { UserRef, UserRefInput } from '@dudousxd/nestjs-authz/store-kit';
export { applyScope, compileScope } from './scope.js';
export type { ScopeResolver } from './scope.js';
