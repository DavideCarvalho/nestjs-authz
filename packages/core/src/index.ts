export const VERSION = '0.0.0';

export { Gate, BoundGate } from './gate.js';
export { PolicyRegistry } from './policy-registry.js';
export { Policy, getPolicyResource } from './decorator/policy.decorator.js';
export { Can } from './decorator/can.decorator.js';
export type { CanMetadata, CanOptions } from './decorator/can.decorator.js';
export { CanGuard } from './guard/can.guard.js';
export { AuthzModule } from './module.js';
export { IdParamResourceResolver } from './resource-resolver.js';
export type { ResourceResolver } from './resource-resolver.js';
export type { ContextAccessor, ContextStore, UserRef } from './context-accessor.js';
export type { PermissionProvider } from './permission-provider.js';
export {
  AUTHZ_MODULE_OPTIONS,
  RESOURCE_RESOLVER,
  CONTEXT_ACCESSOR,
  PERMISSION_PROVIDER,
  POLICY_RESOURCE_METADATA,
  CAN_METADATA,
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
