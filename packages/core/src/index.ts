export const VERSION = '0.0.0';

export { Gate, BoundGate } from './gate.js';
export {
  AUTHZ_DECISION_CHANNEL,
  authzDecisionChannel,
  publishAuthzDecision,
} from './diagnostics.js';
export type { AuthzDecisionDiagnostic, AuthzDecisionReason } from './diagnostics.js';
export { PolicyRegistry } from './policy-registry.js';
export { Policy, getPolicyResource } from './decorator/policy.decorator.js';
export { Can } from './decorator/can.decorator.js';
export type { CanMetadata, CanOptions } from './decorator/can.decorator.js';
export { Roles } from './decorator/roles.decorator.js';
export { CanGuard } from './guard/can.guard.js';
export { RolesGuard } from './guard/roles.guard.js';
export { AuthzModule } from './module.js';
export {
  createCanController,
  DEFAULT_CAN_ENDPOINT_PATH,
} from './can-endpoint.controller.js';
export type { CanRequestBody, CanResponseBody } from './can-endpoint.controller.js';
export { IdParamResourceResolver } from './resource-resolver.js';
export type { ResourceResolver } from './resource-resolver.js';
export type { ContextAccessor, ContextStore, UserRef } from './context-accessor.js';
export type { PermissionProvider } from './permission-provider.js';
export { defaultRoleResolver } from './role-provider.js';
export type { RoleProvider, RoleResolver } from './role-provider.js';
export {
  AUTHZ_MODULE_OPTIONS,
  RESOURCE_RESOLVER,
  CONTEXT_ACCESSOR,
  PERMISSION_PROVIDER,
  ROLE_PROVIDER,
  POLICY_RESOURCE_METADATA,
  CAN_METADATA,
  ROLES_METADATA,
} from './tokens.js';
export {
  AuthzException,
  PolicyNotDecoratedException,
  AbilityNotResolvedException,
  AmbiguousAbilityException,
  ResourceResolverMissingException,
} from './errors/exceptions.js';
export type {
  AuthzModuleOptions,
  AuthzModuleAsyncOptions,
  AuthzModuleOptionsFactory,
  GateFn,
  PolicyBeforeHook,
  PolicyInstance,
  PolicyMethod,
  Resource,
  SuperAdminHook,
  User,
} from './types.js';
