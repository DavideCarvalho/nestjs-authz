import type { Type } from '@nestjs/common';
import type { UserRef } from './context-accessor.js';
import type { ResourceResolver } from './resource-resolver.js';

/**
 * A resource instance passed to policy methods. `unknown` because authz never
 * inspects the resource itself — the policy method does.
 */
export type Resource = object;

/**
 * The current user as seen by a policy/gate. authz does not model the user; it
 * is whatever the app's auth layer produced (or `undefined` when unauthenticated).
 */
export type User = unknown;

/**
 * A policy method: decides a single ability for a `(user, resource?)` pair.
 * Class-level abilities (e.g. `create`) omit the resource. May be async.
 */
export type PolicyMethod = (user: User, resource?: Resource) => boolean | Promise<boolean>;

/**
 * Optional per-policy `before` hook. Runs before the ability method.
 * - return `true`  → allow (short-circuit)
 * - return `false` → deny (short-circuit)
 * - return `void`/`undefined` → fall through to the ability method
 */
export type PolicyBeforeHook = (
  user: User,
  ability: string,
) => boolean | undefined | Promise<boolean | undefined>;

/** A policy instance is an arbitrary object whose methods are abilities. */
export type PolicyInstance = Record<string, unknown> & {
  before?: PolicyBeforeHook;
};

/**
 * An ad-hoc gate: a model-less ability resolved by name via `gate.define`.
 */
export type GateFn = (user: User, resource?: Resource) => boolean | Promise<boolean>;

/**
 * Global super-admin before-hook. Runs before any policy/gate; truthy → allow.
 * `void`/`undefined`/`false` falls through to normal resolution.
 */
export type SuperAdminHook = (
  user: User,
  ability: string,
) => boolean | undefined | Promise<boolean | undefined>;

export interface AuthzModuleOptions {
  /**
   * Policy classes to register explicitly. Each must be decorated with
   * `@Policy(Resource)`. Auto-discovery of `@Policy` providers also works, so
   * this is optional.
   */
  policies?: Array<Type<PolicyInstance>>;
  /**
   * Global super-admin before-hook applied to every authorization check. Return
   * `true` to grant (e.g. super-admins). Returning `void`/`false` falls through.
   *
   * ⚠️ IMPORTANT — what `user` is: on the **context path** (no `forUser`), the
   * `user` passed here is the raw {@link UserRef} from nestjs-context — just
   * `{ type, id }`, NOT your hydrated user entity. So `superAdmin: u => u.isAdmin`
   * will NOT fire from a route/`gate.allows(...)` unless you also configure
   * {@link AuthzModuleOptions.resolveUser} to hydrate the full entity. On the
   * explicit `gate.forUser(entity)` path you receive exactly what you passed.
   */
  superAdmin?: SuperAdminHook;
  /**
   * Optional hook to hydrate the full user entity from the context's
   * {@link UserRef} (`{ type, id }`) before policies / `before` / `superAdmin`
   * run. WITHOUT this hook, the context path passes only `{ type, id }` to those
   * functions (it does not load your `User` row), so property checks such as
   * `superAdmin: u => u.isAdmin` or `post.authorId === user.id` against a real
   * column will not see hydrated fields. Provide `resolveUser` to load the entity
   * (e.g. from your ORM) keyed by the ref. Returning `undefined` is treated as
   * "no user" (deny path), identical to an anonymous request.
   *
   * Only affects the context path; `gate.forUser(entity)` always uses the value
   * you pass directly and never invokes this hook.
   */
  resolveUser?: (ref: UserRef) => User | undefined | Promise<User | undefined>;
  /**
   * Override the default {@link RoleResolver} used by coarse role-checks
   * (`gate.hasRole('teacher')`, `@Roles('admin')`). The default reads `user.roles`
   * (`string[]`) OR `user.role` (`string | string[]`) off the user object, so
   * role-checks work with ZERO RBAC tables. Provide this to derive roles from a
   * different shape. When the optional `ROLE_PROVIDER` seam is ALSO registered, the
   * Gate unions both sources' roles.
   *
   * On the context path the resolver receives whatever the context produced (the
   * raw {@link UserRef} unless `resolveUser` hydrated the entity); on the explicit
   * `gate.forUser(entity)` path it receives exactly what you passed.
   */
  resolveRoles?: (user: User) => string[] | undefined | Promise<string[] | undefined>;
  /**
   * Override the default {@link ResourceResolver} used to load an instance for
   * `@Can(ability, Resource)` routes. Defaults to {@link IdParamResourceResolver}
   * (reads the route `:id` param), registered automatically by `forRoot`. Apps
   * needing real ORM entities provide their own here (or bind the
   * `RESOURCE_RESOLVER` token directly).
   */
  resourceResolver?: ResourceResolver;
  /**
   * Route param name the default {@link IdParamResourceResolver} reads to build
   * the resource shim. Defaults to `'id'`. Ignored when {@link resourceResolver}
   * is supplied.
   */
  idParam?: string;
  /**
   * Opt-in `POST /authz/can` fallback endpoint. **Off by default.** When enabled,
   * registers a controller that runs `gate.allows(ability, resource?)` for the
   * current (context) user and returns `{ allowed: boolean }`. This is the
   * last-resort path the codegen-emitted `can()` helper targets.
   *
   * - `true` → mount at the default path `authz/can`.
   * - `string` → mount at that path (e.g. `'api/authz/can'`).
   * - `false`/omitted → no endpoint is registered.
   *
   * Prefer the no-request paths (shared Inertia props, per-resource `can` maps)
   * — this endpoint exists only for abilities not already hydrated on the client.
   */
  canEndpoint?: boolean | string;
}

export interface AuthzModuleOptionsFactory {
  createAuthzOptions(): Promise<AuthzModuleOptions> | AuthzModuleOptions;
}

export interface AuthzModuleAsyncOptions {
  imports?: unknown[];
  useExisting?: Type<AuthzModuleOptionsFactory>;
  useClass?: Type<AuthzModuleOptionsFactory>;
  useFactory?: (...args: unknown[]) => Promise<AuthzModuleOptions> | AuthzModuleOptions;
  inject?: unknown[];
  /**
   * Opt-in `POST /authz/can` fallback endpoint (see {@link AuthzModuleOptions.canEndpoint}).
   * Declared statically here because controllers are registered at module-definition
   * time, before the async options factory resolves. Off by default.
   */
  canEndpoint?: boolean | string;
}
