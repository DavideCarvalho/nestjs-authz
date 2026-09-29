export {
  PRISMA_AUTHZ_STORE_OPTIONS,
  PRISMA_CLIENT,
  type PrismaAuthzClientLike,
  type PrismaAuthzStoreOptions,
  type PrismaModelDelegate,
} from './prisma-client.js';
export { PrismaAuthzStore } from './prisma-authz.store.js';
export type {
  RoleAssignment,
  RoleAssignmentFilter,
  RoleSourceOptions,
  UserAuthz,
  UserRoleAssignment,
} from './prisma-authz.store.js';
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
export type { UserRef, UserRefInput } from '@dudousxd/nestjs-authz/store-kit';
export { applyScope, compileScope } from './scope.js';
export type { PrismaWhere, ScopeResolver } from './scope.js';
