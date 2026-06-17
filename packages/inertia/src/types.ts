import type { ArgumentsHost, ForbiddenException } from '@nestjs/common';
import type { AbilityNamer, CanMap } from './resolve-abilities.js';

/**
 * Configures the {@link AuthzDenialFilter}: how authorization denials
 * (`@Roles`/`@Can` → `ForbiddenException`) render on Inertia requests. Non-Inertia
 * (REST) requests are unaffected — they keep the normal 403 JSON.
 */
export interface AuthzDenialOptions {
  /**
   * Disable the filter entirely (it is registered unconditionally; this opts
   * out at runtime, leaving the raw 403 for Inertia requests too).
   *
   * Default: `true` (denials redirect on Inertia requests).
   */
  enabled?: boolean;
  /**
   * Redirect target for an UNAUTHENTICATED denial (no `CONTEXT_ACCESSOR` user).
   *
   * Default: `'/login'`.
   */
  loginUrl?: string;
  /**
   * Redirect target for an AUTHENTICATED-but-FORBIDDEN denial.
   *
   * Default: `'/403'`.
   */
  forbiddenUrl?: string;
  /**
   * Escape hatch: fully handle the denial on an Inertia request yourself (e.g.
   * render an error page instead of redirecting). Receives the thrown
   * `ForbiddenException` and the `ArgumentsHost`. When provided, it replaces the
   * default redirect behavior for Inertia requests.
   */
  handler?: (exception: ForbiddenException, host: ArgumentsHost) => void;
}

/**
 * Minimal structural mirror of the request object carrying `req.inertia`, set by
 * `@dudousxd/nestjs-inertia`'s middleware. We deliberately do NOT import the
 * InertiaService type to keep the coupling structural (the real service satisfies
 * this shape). `share(input)` merges `input` into the page's shared props.
 */
export interface InertiaShareable {
  share(input: Record<string, unknown>): unknown;
}

/** A request that may carry an attached Inertia service. */
export interface RequestWithInertia {
  inertia?: InertiaShareable;
}

export interface AuthzInertiaOptions {
  /**
   * Prop key the resolved ability map is shared under. The client store reads
   * `props.auth.can`, so the default nests the map at `auth.can`. Override to
   * change the namespace (e.g. `'abilities'` → `props.abilities`).
   *
   * Default: `'auth'` → `{ auth: { can: { ... } } }`.
   */
  propKey?: string;
  /**
   * Extra ad-hoc ability names to resolve in addition to auto-discovered gates.
   */
  abilities?: string[];
  /**
   * Build a policy ability name from `(resourceClassName, method)`. Defaults to
   * `"<resourceLower>.<method>"`. Use `(_, m) => m` for bare method names.
   */
  abilityNamer?: AbilityNamer;
  /**
   * Also emit the bare policy method name as a key alongside the namespaced one.
   * Default `false`.
   */
  includeBareMethodNames?: boolean;
  /**
   * Configures how authorization denials render on Inertia requests via the
   * {@link AuthzDenialFilter}. Omit to use the defaults (redirect on; `/login`
   * unauthenticated, `/403` forbidden).
   */
  denial?: AuthzDenialOptions;
}

/** The shape shared into props (under {@link AuthzInertiaOptions.propKey}). */
export interface SharedAuthProps {
  can: CanMap;
}
