// Rewritten from this package's package.json by `scripts/sync-version.mjs`, which the root
// `version-packages` script runs right after `changeset version`. The build is plain `tsc`
// and injects nothing, so the literal below is what ships in dist.
export const VERSION = '0.12.0';

// Extras on top of @nestjs/authorization. Its own API (@Policy, @Can, Can.Anyone,
// AuthorizationModule, AuthorizationService, AuthorizationGuard) is imported from there.

export { AuthzModule } from './module.js';
// Migration mode: `AuthzModule.forRoot({ unannotated: 'allow' })`
export { AuthzGuard } from './authz.guard.js';
export { Gate, BoundGate } from './gate.js';
export type {
  AbilityArgsOf,
  BatchAbility,
  BatchItem,
  BatchPolicyCheck,
  BatchResult,
  GateExplanation,
} from './gate.js';

// Official policies and the super-admin base class
export {
  AuthzPolicy,
  superAdminBefore,
  decisionProviderBefore,
  RolePolicy,
  PermissionPolicy,
  GatePolicy,
} from './policies/index.js';

// Helpers for the official @Can()
export {
  STATIC_CAN_ARGS,
  staticCanArgs,
  getStaticCanArgs,
  byId,
  roles,
  permission,
  permissions,
  ability,
  authorizedResource,
} from './helpers.js';
export type { ByIdOptions, CanArgsResolver } from './helpers.js';
export { Roles, Permission } from './decorator/roles.decorator.js';

// Resource ↔ policy link
export { PolicyFor, policyForResource, getPolicyResource, policyLinks } from './links.js';
export { PolicyIndex } from './policy-index.js';
export type { IndexedPolicy } from './policy-index.js';

// Reading the official metadata
export {
  OFFICIAL_POLICY_METADATA,
  OFFICIAL_CAN_METADATA,
  OFFICIAL_CAN_ANYONE_METADATA,
  OFFICIAL_PUBLIC_METADATA,
  isOfficialPolicy,
  readCanRequirements,
  routeRequirements,
} from './official.js';
export type { OfficialCanRequirement } from './official.js';
export { currentUserOf } from './runtime.js';

// RBAC seams
export { AuthzRbac } from './rbac.js';
export type { PermissionProvider } from './permission-provider.js';
export { defaultRoleResolver } from './role-provider.js';
export type { RbacDescription, RoleProvider, RoleResolver } from './role-provider.js';
export {
  TENANT_SCOPE_SLOT,
  currentTenantScopeOverride,
  runInTenantScope,
  runWithoutRequiredTenant,
} from './tenant-override.js';
export type { TenantScopeOverride } from './tenant-override.js';

// Dev MCP tools (`@dudousxd/nestjs-agent-mcp-server`'s dev endpoint)
export {
  AuthzDevTools,
  DEV_TOOLS_SLOT,
  authzDevTools,
  registerAuthzDevTools,
} from './dev-tools.js';
export type {
  AuthzDevTool,
  AuthzDevToolsDeps,
  AuthzDevToolsOptions,
  AuthzDevToolsRef,
  DevToolCall,
  DevToolInputProperty,
  DevToolInputSchema,
  DevToolsRegistration,
} from './dev-tools.js';
export {
  CompiledPermissions,
  permissionMatches,
  permissionSatisfied,
} from './permission-matcher.js';
export { PermissionCache } from './permission-cache.js';

// External decision point (Cerbos adapter: `@dudousxd/nestjs-authz/cerbos`)
export { normalizeVerdict } from './decision-provider.js';
export type {
  DecisionProvider,
  DecisionRequest,
  DecisionVerdict,
} from './decision-provider.js';

// Decisions
export { authzDecisionChannel, publishAuthzDecision } from './diagnostics.js';
export type {
  AuthzDecisionDiagnostic,
  AuthzDecisionReason,
  AuthzDecisionSource,
} from './diagnostics.js';
export { AuthzDecisionPublisher } from './decisions.js';

// Aviary console access (`authorize` on the durable/telescope/media/agent consoles)
export {
  AuthzConsoleGate,
  CONSOLE_GATE,
  authorizeByPermission,
  authorizeByRoles,
  authorizeByToken,
} from './console.js';
export type {
  ConsoleAuthorize,
  ConsoleAuthorizeResult,
  ConsoleAuthorizer,
  ConsoleAuthorizerClass,
  ConsoleLoginOptions,
  ConsolePolicyCheck,
} from './console.js';

// Client endpoint
export { createCanController, DEFAULT_CAN_ENDPOINT_PATH } from './can-endpoint.controller.js';
export type {
  CanRequestBody,
  CanResponseBody,
  CanBatchRequestBody,
  CanBatchResultItem,
} from './can-endpoint.controller.js';

export { IdParamResourceResolver } from './resource-resolver.js';
export type { ResourceResolver, ResourceResolveHints } from './resource-resolver.js';
export type { ContextAccessor, ContextStore, UserRef } from './context-accessor.js';

// Query scoping
export {
  and,
  eq,
  SAFE_IDENTIFIER,
  assertSafeIdentifier,
  normalizeScope,
  or,
  scopeAll,
  scopeNone,
  where,
} from './scope.js';
export type {
  ScopeAll,
  ScopeCondition,
  ScopeConstraint,
  ScopeGroup,
  ScopeMethod,
  ScopeNode,
  ScopeNone,
  ScopeOperator,
  ScopeResult,
} from './scope.js';

export {
  AUTHZ_MODULE_OPTIONS,
  RESOURCE_RESOLVER,
  RESOURCE_HYDRATOR,
  CONTEXT_ACCESSOR,
  DECISION_PROVIDER,
  PERMISSION_PROVIDER,
  ROLE_PROVIDER,
  POLICY_RESOURCE_METADATA,
} from './tokens.js';
export {
  AuthzException,
  AbilityNotResolvedException,
  AmbiguousAbilityException,
} from './errors/exceptions.js';
export type {
  AuthzModuleOptions,
  AuthzModuleAsyncOptions,
  AuthzModuleOptionsFactory,
  AuthzModuleStaticOptions,
  UnannotatedRoutes,
  GateFn,
  PolicyResponse,
  PolicyResult,
  Resource,
  ResourceLoader,
  ResourceLoaderMap,
  SuperAdminHook,
  User,
} from './types.js';
