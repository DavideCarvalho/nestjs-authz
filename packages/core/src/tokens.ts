/** Injection token holding the resolved {@link AuthzModuleOptions}. */
export const AUTHZ_MODULE_OPTIONS = Symbol.for('@dudousxd/nestjs-authz:options');

/** Injection token for the optional {@link ResourceResolver} registered by the app. */
export const RESOURCE_RESOLVER = Symbol.for('@dudousxd/nestjs-authz:resource-resolver');

/**
 * Injection token holding the optional resource-loader map consulted by the opt-in
 * `POST /authz/can` endpoint to rehydrate a `{ type, id }` shim into the REAL entity
 * instance before authorizing — so an instance-bound `@Policy` matches by constructor.
 *
 * Resolves to a `ResourceLoaderMap` (`Record<type, (id) => instance | Promise<instance>>`)
 * keyed by the resource `type` name the client/codegen emits. Populated from the
 * `resourceLoaders` forRoot option; an adapter MAY also bind this token to register
 * loaders, mirroring the {@link PERMISSION_PROVIDER}/{@link ROLE_PROVIDER} seam.
 *
 * Shared via `Symbol.for(key)` (global registry) so an external package binding this
 * same key resolves to the SAME symbol instance. Consulted with `@Optional()` — absent
 * or empty, the endpoint behaves exactly as before (class-level / ad-hoc only).
 */
export const RESOURCE_HYDRATOR = Symbol.for('@dudousxd/nestjs-authz:resource-hydrator');

/** Metadata key for `@Policy(Resource)` — stores the resource class on the policy. */
export const POLICY_RESOURCE_METADATA = 'nestjs-authz:policy-resource';

/** Metadata key for `@Can(ability, Resource?)` — stores the ability descriptor on a route. */
export const CAN_METADATA = 'nestjs-authz:can';

/** Metadata key for `@Roles(...roles)` — stores the allowed role names on a route. */
export const ROLES_METADATA = 'nestjs-authz:roles';

/**
 * Cross-lib injection token for an optional {@link PermissionProvider} — the seam the
 * RBAC adapter (`@dudousxd/nestjs-authz-typeorm`) registers so that a model-less,
 * named ability (`gate.allows('posts.publish')`) is granted when the current user
 * holds that persisted permission. This is the Laravel/spatie `Gate::before` grant.
 *
 * `Symbol.for(key)` uses the global symbol registry so an RBAC package registering
 * this same key resolves to the SAME symbol instance without importing core internals.
 * The token is consulted with `@Optional()` — when absent, the Gate behaves exactly
 * as before (backward-compatible: unknown abilities still throw).
 */
export const PERMISSION_PROVIDER = Symbol.for('@dudousxd/nestjs-authz:permission-provider');

/**
 * Cross-lib injection token for an optional {@link RoleProvider} — the seam an RBAC
 * adapter (`@dudousxd/nestjs-authz-typeorm`) registers so coarse role-checks
 * (`gate.hasRole('teacher')`, `@Roles('admin')`) consult a persisted role store.
 *
 * Like {@link PERMISSION_PROVIDER}, it shares the global symbol registry via
 * `Symbol.for(key)` so an RBAC package registering this same key resolves to the
 * SAME symbol instance without importing core internals. Consulted with
 * `@Optional()`: when absent, only the default {@link RoleResolver} (roles read off
 * the user object) supplies roles. When BOTH yield roles, the Gate unions them.
 */
export const ROLE_PROVIDER = Symbol.for('@dudousxd/nestjs-authz:role-provider');

/**
 * Cross-lib injection token for the current-request context accessor, owned by
 * `@dudousxd/nestjs-context`. We do NOT import nestjs-context — instead we share
 * its well-known token by value so DI resolves the same provider when present.
 *
 * `Symbol.for(key)` uses the global symbol registry, so this resolves to the
 * SAME symbol instance as nestjs-context's `tokens.ts` without any import.
 * The key MUST stay byte-identical with nestjs-context's export.
 */
export const CONTEXT_ACCESSOR = Symbol.for('@dudousxd/nestjs-context:accessor');
