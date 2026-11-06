import type { Type } from '@nestjs/common';
import type { UserRef } from './context-accessor.js';
import type { ResourceResolver } from './resource-resolver.js';

/** A resource passed to a policy ability. authz never inspects it; the policy does. */
export type Resource = object;

/**
 * The user a policy or gate sees: whatever authentication produced, `null` for a
 * guest. authz does not model it.
 */
export type User = unknown;

/**
 * A verdict with an optional reason. What a {@link DecisionProvider} may answer instead of
 * a bare boolean; the `message` is published on the decision event.
 */
export interface PolicyResponse {
  allowed: boolean;
  message?: string;
}

/** A bare boolean or a {@link PolicyResponse}. */
export type PolicyResult = boolean | PolicyResponse;

/** An ad-hoc, model-less gate registered with `gate.define(name, fn)`. */
export type GateFn = (user: User, resource?: Resource) => boolean | Promise<boolean>;

/**
 * The global super-admin hook. `true` grants any check; anything else falls through.
 * Policies honor it when they extend `AuthzPolicy` (or call `superAdminBefore` from
 * their `before()`); `RolePolicy` and `PermissionPolicy` do. The `Gate`'s string
 * abilities and `gate.scope()` ask it first.
 */
export type SuperAdminHook = (
  user: User,
  ability: string,
  /**
   * What the check targets: the resource of a single check (the policy's first
   * argument), or the entity class for `gate.scope(...)`. `undefined` for a model-less
   * ability. Lets the hook scope the bypass (e.g. to one tenant's resources).
   */
  resource?: Resource,
) => boolean | null | undefined | Promise<boolean | null | undefined>;

/** Loads the real entity for a client `{ type, id }` reference (the `POST /authz/can` endpoint). */
export type ResourceLoader = (id: string | number) => unknown | Promise<unknown>;

/** Resource loaders keyed by the resource `type` name the client sends (e.g. `'Post'`). */
export type ResourceLoaderMap = Record<string, ResourceLoader>;

export interface AuthzModuleOptions {
  /** The global super-admin hook. See {@link SuperAdminHook}. */
  superAdmin?: SuperAdminHook;
  /**
   * Hydrates the full user from nestjs-context's `{ type, id }` ref for `Gate` calls
   * made without a user (`gate.allows(...)` rather than `gate.forUser(user)`), when
   * `@nestjs/authentication`'s `AuthenticationContext` has no user to offer. Runs once
   * per `type:id` per request (nestjs-context store). Routes never use it: the official
   * guard reads the user with its own `getUser`.
   */
  resolveUser?: (ref: UserRef) => User | undefined | Promise<User | undefined>;
  /**
   * Derives roles from the user object. Default: `user.roles` (`string[]`) or
   * `user.role` (`string | string[]`). Unioned with the RBAC adapter's role store.
   */
  resolveRoles?: (user: User) => string[] | undefined | Promise<string[] | undefined>;
  /** Loads the resource for `byId(Resource)`. Default: {@link IdParamResourceResolver}. */
  resourceResolver?: ResourceResolver;
  /** Route param the default resolver reads. Default `'id'`. */
  idParam?: string;
  /**
   * Opt-in `POST /authz/can` endpoint for client checks that are not hydrated. `true`
   * mounts it at `authz/can`; a string at that path. Off by default.
   */
  canEndpoint?: boolean | string;
  /** Loaders that turn the endpoint's `{ type, id }` into the real entity, keyed by type. */
  resourceLoaders?: ResourceLoaderMap;
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
  /** See {@link AuthzModuleOptions.canEndpoint}. Static: controllers are registered before the factory runs. */
  canEndpoint?: boolean | string;
  /** See {@link AuthzModuleOptions.resourceLoaders}. */
  resourceLoaders?: ResourceLoaderMap;
}
