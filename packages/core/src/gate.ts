import { ForbiddenException, Inject, Injectable, Optional, type Type } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import type { ContextAccessor, ContextStore, UserRef } from './context-accessor.js';
import { type AuthzDecisionReason, publishAuthzDecision } from './diagnostics.js';
import { AbilityNotResolvedException, AmbiguousAbilityException } from './errors/exceptions.js';
import { PermissionCache } from './permission-cache.js';
import { permissionSatisfied } from './permission-matcher.js';
import type { PermissionProvider } from './permission-provider.js';
import { PolicyRegistry } from './policy-registry.js';
import { type RoleProvider, type RoleResolver, defaultRoleResolver } from './role-provider.js';
import {
  type ScopeConstraint,
  type ScopeMethod,
  normalizeScope,
  scopeAll,
  scopeNone,
} from './scope.js';
import {
  AUTHZ_MODULE_OPTIONS,
  CONTEXT_ACCESSOR,
  PERMISSION_PROVIDER,
  ROLE_PROVIDER,
} from './tokens.js';
import type {
  AfterHook,
  AuthzModuleOptions,
  GateFn,
  PolicyBeforeHook,
  PolicyInstance,
  PolicyResult,
  Resource,
  SuperAdminHook,
  User,
} from './types.js';

/**
 * A normalized hook/policy return: an explicit verdict (or `undefined` = "no
 * opinion / fall through") plus an optional deny message. Bare booleans, the
 * richer `{ allowed, message }` shape, and nullish all map here.
 */
interface NormalizedResult {
  allowed: boolean | undefined;
  message?: string;
}

/** Normalize a `boolean | PolicyResponse | null | undefined` into a {@link NormalizedResult}. */
function normalizeResult(value: PolicyResult | undefined): NormalizedResult {
  if (value == null) return { allowed: undefined };
  if (typeof value === 'boolean') return { allowed: value };
  // `exactOptionalPropertyTypes`: only attach `message` when actually present.
  return value.message === undefined
    ? { allowed: Boolean(value.allowed) }
    : { allowed: Boolean(value.allowed), message: value.message };
}

/**
 * Attach `message` to a decision only when defined (honors `exactOptionalPropertyTypes`,
 * which forbids an explicit `message: undefined` on an optional property).
 */
function withMessage<T extends { reason: AuthzDecisionReason; allowed: boolean | undefined }>(
  decision: T,
  message: string | undefined,
): T & { message?: string } {
  return message === undefined ? decision : { ...decision, message };
}

/**
 * Build the `ForbiddenException` for a denied `authorize(...)`, surfacing the
 * decision's `reason` (and the policy/hook `message` when present) instead of
 * discarding it. The message string defaults to the generic `Unauthorized: <ability>`
 * for backward compatibility; the structured body carries `ability` + `reason` so a
 * 403 is debuggable by clients and the diagnostics watcher alike.
 */
function forbidden(
  ability: string,
  decision: { reason: AuthzDecisionReason; message?: string },
): ForbiddenException {
  const message = decision.message ?? `Unauthorized: ${ability}`;
  return new ForbiddenException({
    statusCode: 403,
    error: 'Forbidden',
    message,
    ability,
    reason: decision.reason,
  });
}

// A sentinel marking "no user resolved" distinct from a legitimately-`undefined`
// user. `forUser(undefined)` explicitly authorizes an anonymous user.
const NO_USER = Symbol('authz:no-user');
type MaybeUser = User | typeof NO_USER;

/**
 * Key under which the per-request {@link PermissionCache} is stashed on the
 * nestjs-context store. `Symbol.for` so the same key resolves across copies of
 * this module (e.g. multiple installs in a monorepo) sharing one store.
 */
const REQUEST_PERMISSION_CACHE = Symbol.for('@dudousxd/nestjs-authz:request-permission-cache');

/** A single item in a {@link Gate.allowsMany} batch. */
export interface BatchAbility {
  ability: string;
  resource?: Resource;
}

/** A single result from a {@link Gate.allowsMany} batch: the input plus its verdict. */
export interface BatchResult {
  ability: string;
  resource?: Resource;
  allowed: boolean;
}

/**
 * Laravel-style authorization Gate.
 *
 * Resolves an ability against either a registered `@Policy` method (by ability
 * name, matched against the resource's policy) or an ad-hoc gate defined via
 * {@link define}. Applies the global `superAdmin` before-hook and the per-policy
 * `before` hook with short-circuit semantics.
 *
 * The current user comes from the optional {@link ContextAccessor} (nestjs-context)
 * when present, or is supplied explicitly via {@link forUser}.
 */
@Injectable()
export class Gate {
  private readonly gates = new Map<string, GateFn>();
  private readonly superAdmin: SuperAdminHook | undefined;
  private readonly after: AfterHook | undefined;
  private readonly resolveUser: AuthzModuleOptions['resolveUser'];
  private readonly roleResolver: RoleResolver;

  // Memoized ModuleRef seam lookups. These tokens are singletons bound once at
  // module init, so the (potentially throwing) non-strict container scan only
  // needs to run once per seam — never on every authorization check.
  private contextResolved = false;
  private contextCached: ContextAccessor | undefined;
  private permissionProviderResolved = false;
  private permissionProviderCached: PermissionProvider | undefined;
  private roleProviderResolved = false;
  private roleProviderCached: RoleProvider | undefined;

  constructor(
    private readonly policies: PolicyRegistry,
    @Optional()
    @Inject(AUTHZ_MODULE_OPTIONS)
    options: AuthzModuleOptions | undefined,
    @Optional()
    @Inject(CONTEXT_ACCESSOR)
    private readonly context?: ContextAccessor,
    @Optional()
    private readonly moduleRef?: ModuleRef,
    @Optional()
    @Inject(PERMISSION_PROVIDER)
    private readonly permissionProvider?: PermissionProvider,
    @Optional()
    @Inject(ROLE_PROVIDER)
    private readonly roleProvider?: RoleProvider,
  ) {
    this.superAdmin = options?.superAdmin;
    this.after = options?.after;
    this.resolveUser = options?.resolveUser;
    this.roleResolver = options?.resolveRoles ?? defaultRoleResolver;
  }

  /**
   * Locate the context accessor. Prefers the value injected into this module;
   * falls back to a non-strict {@link ModuleRef} lookup so an accessor provided
   * by ANY module (e.g. a global ContextModule, or the app root) is still found.
   */
  private resolveContext(): ContextAccessor | undefined {
    if (this.context) return this.context;
    if (this.contextResolved) return this.contextCached;
    this.contextResolved = true;
    if (!this.moduleRef) return this.contextCached;
    try {
      this.contextCached = this.moduleRef.get<ContextAccessor>(CONTEXT_ACCESSOR, { strict: false });
    } catch {
      this.contextCached = undefined;
    }
    return this.contextCached;
  }

  /**
   * Locate the optional {@link PermissionProvider} (the RBAC seam). Prefers the value
   * injected into this module; falls back to a non-strict {@link ModuleRef} lookup so a
   * provider registered by ANY module (e.g. the RBAC adapter's global module) is found.
   */
  private resolvePermissionProvider(): PermissionProvider | undefined {
    if (this.permissionProvider) return this.permissionProvider;
    if (this.permissionProviderResolved) return this.permissionProviderCached;
    this.permissionProviderResolved = true;
    if (!this.moduleRef) return this.permissionProviderCached;
    try {
      this.permissionProviderCached = this.moduleRef.get<PermissionProvider>(PERMISSION_PROVIDER, {
        strict: false,
      });
    } catch {
      this.permissionProviderCached = undefined;
    }
    return this.permissionProviderCached;
  }

  /**
   * Locate the optional {@link RoleProvider} (the coarse role seam). Prefers the value
   * injected into this module; falls back to a non-strict {@link ModuleRef} lookup so a
   * provider registered by ANY module (e.g. the RBAC adapter's global module) is found.
   */
  private resolveRoleProvider(): RoleProvider | undefined {
    if (this.roleProvider) return this.roleProvider;
    if (this.roleProviderResolved) return this.roleProviderCached;
    this.roleProviderResolved = true;
    if (!this.moduleRef) return this.roleProviderCached;
    try {
      this.roleProviderCached = this.moduleRef.get<RoleProvider>(ROLE_PROVIDER, { strict: false });
    } catch {
      this.roleProviderCached = undefined;
    }
    return this.roleProviderCached;
  }

  /**
   * The per-request {@link PermissionCache}, stashed on the nestjs-context store so
   * every check within one HTTP request shares a single `getPermissions` fetch
   * (kills the N+1 a list page would otherwise cause). Returns `undefined` when no
   * context store is available (standalone use), in which case callers fall back to
   * a transient cache (e.g. one per `allowsMany` batch) or no memoization.
   */
  private resolveRequestCache(): PermissionCache | undefined {
    const context = this.resolveContext();
    // `get()` is part of the ContextAccessor contract but a stub/partial accessor
    // may omit it (or it may throw outside a request scope) — degrade to "no
    // request cache" rather than failing the check.
    if (!context || typeof context.get !== 'function') return undefined;
    let store: ContextStore | undefined;
    try {
      store = context.get();
    } catch {
      store = undefined;
    }
    if (!store) return undefined;
    const existing = (store as Record<symbol, unknown>)[REQUEST_PERMISSION_CACHE];
    if (existing instanceof PermissionCache) return existing;
    const cache = new PermissionCache();
    (store as Record<symbol, unknown>)[REQUEST_PERMISSION_CACHE] = cache;
    return cache;
  }

  /** Register an ad-hoc, model-less gate resolved by `ability` name. */
  define(ability: string, fn: GateFn): this {
    this.gates.set(ability, fn);
    return this;
  }

  /** True when an ad-hoc gate is registered for `ability`. */
  hasGate(ability: string): boolean {
    return this.gates.has(ability);
  }

  /**
   * Names of every ad-hoc gate registered via {@link define}. Used by integrations
   * (e.g. `@dudousxd/nestjs-authz-inertia`) that enumerate the user's class-level
   * abilities to share them as Inertia props — no network round-trip needed.
   */
  gateNames(): string[] {
    return [...this.gates.keys()];
  }

  /**
   * Bind an explicit user, bypassing the context accessor. Use when no
   * nestjs-context is wired, or to check a user other than the current one.
   *
   * A nullish user (`forUser(undefined)` / `forUser(null)`) is an explicit
   * anonymous request: it maps to the same deny path as an unauthenticated
   * context (`NO_USER`), so policies/gates are never invoked with `undefined` and
   * never throw. The `resolveUser` hook is NOT applied to `forUser` — the value
   * you pass is used verbatim.
   */
  forUser(user: User): BoundGate {
    return new BoundGate(this, user == null ? NO_USER : user);
  }

  /**
   * Resolve the current user from the context accessor, or `NO_USER`.
   * When a `resolveUser` hook is configured, hydrate the full entity from the
   * context's {@link UserRef}; a hook returning nullish maps to `NO_USER`.
   */
  private async currentUser(): Promise<MaybeUser> {
    const context = this.resolveContext();
    if (!context) return NO_USER;
    const ref = context.userRef();
    if (ref === undefined) return NO_USER;
    if (this.resolveUser) {
      const hydrated = await this.resolveUser(ref as UserRef);
      return hydrated == null ? NO_USER : hydrated;
    }
    return ref;
  }

  // --- public API (operates on the current/context user) ---

  async allows(ability: string, resource?: Resource): Promise<boolean> {
    return this.check(await this.currentUser(), ability, resource, this.resolveRequestCache());
  }

  async denies(ability: string, resource?: Resource): Promise<boolean> {
    return !(await this.allows(ability, resource));
  }

  async authorize(ability: string, resource?: Resource): Promise<void> {
    const decision = await this.decide(
      await this.currentUser(),
      ability,
      resource,
      this.resolveRequestCache(),
    );
    if (!decision.allowed) throw forbidden(ability, decision);
  }

  /**
   * Authorize MANY abilities for the current (context) user in a single pass. The
   * user is resolved ONCE and a single {@link PermissionCache} is shared across all
   * items, so a list page (N cards) costs one user resolution + at most one
   * permission fetch instead of N of each. Order is preserved; each result echoes
   * its input `ability`/`resource` plus the `allowed` verdict.
   *
   * Fault-isolating: an item whose ability is unresolved/ambiguous denies just
   * THAT item (it does not throw and abort the batch) — a batch is a best-effort
   * verdict list, not an enforcement gate.
   */
  async allowsMany(items: BatchAbility[]): Promise<BatchResult[]> {
    return this.checkMany(await this.currentUser(), items);
  }

  /**
   * Resolve the QUERY SCOPE constraint for the current (context) user against
   * `entity` — the `accessibleBy` / Pundit `policy_scope` concept. Returns an
   * ORM-neutral {@link ScopeConstraint} an adapter (e.g. the TypeORM `applyScope`
   * helper) turns into a parameterized `WHERE`.
   *
   * Consistent with the Gate's single-resource semantics:
   * - super-admin / before-grant / permission-provider grant → `allow-all`,
   * - anonymous, or no policy/scope → `deny-all` (default-deny),
   * - otherwise the policy's `scope` (or `viewAny`-style) constraint.
   *
   * `ability` (default `'viewAny'`) names the permission-provider check used for
   * the allow-all grant and the policy fallback method.
   */
  async scope(entity: Type<unknown>, ability = 'viewAny'): Promise<ScopeConstraint> {
    return this.resolveScope(await this.currentUser(), entity, ability);
  }

  // --- coarse role checks (operate on the current/context user) ---

  /** True when the current user holds `role`. */
  async hasRole(role: string): Promise<boolean> {
    return this.checkRoles(await this.currentUser(), [role]);
  }

  /** True when the current user holds ANY of `roles`. */
  async hasAnyRole(roles: string[]): Promise<boolean> {
    return this.checkRoles(await this.currentUser(), roles);
  }

  // --- internal: used by BoundGate too ---

  /** @internal */
  allowsForUser(user: MaybeUser, ability: string, resource?: Resource): Promise<boolean> {
    return this.check(user, ability, resource, this.resolveRequestCache());
  }

  /** @internal — batch check for an explicit/bound user (see {@link allowsMany}). */
  allowsManyForUser(user: MaybeUser, items: BatchAbility[]): Promise<BatchResult[]> {
    return this.checkMany(user, items);
  }

  /**
   * Run a batch of checks against one already-resolved user, sharing a single
   * {@link PermissionCache} so the provider's `getPermissions` runs at most once.
   * Prefers the per-request cache (so the batch also coalesces with other checks in
   * the same request); falls back to a transient per-batch cache when standalone.
   */
  private async checkMany(user: MaybeUser, items: BatchAbility[]): Promise<BatchResult[]> {
    const cache = this.resolveRequestCache() ?? new PermissionCache();
    const out: BatchResult[] = [];
    for (const item of items) {
      let allowed: boolean;
      try {
        allowed = await this.check(user, item.ability, item.resource, cache);
      } catch {
        // Unresolved/ambiguous ability → deny just this item (don't abort the batch).
        allowed = false;
      }
      out.push(
        item.resource === undefined
          ? { ability: item.ability, allowed }
          : { ability: item.ability, resource: item.resource, allowed },
      );
    }
    return out;
  }

  /** @internal — used by {@link BoundGate.authorize} to surface the deny reason/message. */
  decideForUser(
    user: MaybeUser,
    ability: string,
    resource?: Resource,
  ): Promise<{ allowed: boolean; reason: AuthzDecisionReason; message?: string }> {
    return this.decide(user, ability, resource, this.resolveRequestCache());
  }

  /** @internal */
  hasAnyRoleForUser(user: MaybeUser, roles: string[]): Promise<boolean> {
    return this.checkRoles(user, roles);
  }

  /** @internal — used by {@link BoundGate.scope}. */
  scopeForUser(
    user: MaybeUser,
    entity: Type<unknown>,
    ability = 'viewAny',
  ): Promise<ScopeConstraint> {
    return this.resolveScope(user, entity, ability);
  }

  /**
   * Resolve a query-scope constraint for `entity`, mirroring {@link resolveBase}'s
   * grant order so scoping stays consistent with single-resource decisions:
   *
   * 1. super-admin hook grants → `allow-all`;
   * 2. (authenticated) permission-provider grant for `ability` → `allow-all`;
   * 3. the policy's `scope` (or `viewAny`-style) method → its constraint;
   * 4. otherwise (anonymous, no policy, no scope method) → `deny-all`.
   *
   * The policy `before` hook is also honored as an allow/deny grant before the
   * scope method runs, so a policy that broadly allows/denies in `before` scopes
   * the same way it decides.
   */
  private async resolveScope(
    maybeUser: MaybeUser,
    entity: Type<unknown>,
    ability: string,
  ): Promise<ScopeConstraint> {
    const user: User = maybeUser === NO_USER ? undefined : maybeUser;

    // 1. Global super-admin hook → allow-all (a `false` does not deny here, it
    //    just falls through, mirroring resolveBase's grant-or-fall-through).
    const sa = normalizeResult(await this.superAdmin?.(user, ability));
    if (sa.allowed === true) return scopeAll;

    // 2. Permission-provider grant for the scope ability → allow-all.
    if (
      maybeUser !== NO_USER &&
      (await this.permissionProviderGrants(user, ability, undefined, this.resolveRequestCache()))
    ) {
      return scopeAll;
    }

    // 3. Policy scope (or viewAny-style fallback) method.
    const policy = this.policies.forResource(entity);
    if (policy) {
      const scopeMethod = this.resolveScopeMethod(policy, ability);
      if (scopeMethod) {
        const before = (policy as PolicyInstance).before as PolicyBeforeHook | undefined;
        if (typeof before === 'function') {
          const result = normalizeResult(await before.call(policy, user, ability));
          if (result.allowed === true) return scopeAll;
          if (result.allowed === false) return scopeNone;
        }
        // Anonymous users see no rows (default-deny, like the single-resource path).
        if (maybeUser === NO_USER) return scopeNone;
        return normalizeScope(await scopeMethod.call(policy, user, entity));
      }
    }

    // 4. No way to scope → deny-all.
    return scopeNone;
  }

  /**
   * Pick the policy's scope method: the conventional `scope`, else the `ability`
   * method (e.g. `viewAny`) when it is scope-shaped. Returns `undefined` when the
   * policy declares neither.
   */
  private resolveScopeMethod(policy: PolicyInstance, ability: string): ScopeMethod | undefined {
    const scope = (policy as Record<string, unknown>).scope;
    if (typeof scope === 'function') return scope as ScopeMethod;
    const fallback = (policy as Record<string, unknown>)[ability];
    if (typeof fallback === 'function') return fallback as ScopeMethod;
    return undefined;
  }

  /**
   * Whether the registered {@link PermissionProvider} grants `ability` for an authenticated `user` —
   * the RBAC "before" grant shared by the single-resource ({@link resolveBase}) and scope
   * ({@link resolveScope}) paths, single-sourced here so the grant order can't drift between them.
   *
   * Grant-only: a `false`/nullish result is "no grant", never a deny. When the provider lists the
   * user's granted permissions, segment-based wildcard matching runs in the core (a granted
   * `posts.*` satisfies `posts.update`, `*` satisfies anything) regardless of adapter; a nullish
   * list defers to the exact-match `hasPermission`. The granted set is fetched through `cache` when
   * one is supplied, else via a direct fetch.
   */
  private async permissionProviderGrants(
    user: User,
    ability: string,
    resource: Resource | undefined,
    cache: PermissionCache | undefined,
  ): Promise<boolean> {
    const provider = this.resolvePermissionProvider();
    if (!provider) return false;
    if (typeof provider.getPermissions === 'function') {
      const satisfied = cache
        ? await cache.satisfies(provider, user, ability)
        : await (async () => {
            const granted = await provider.getPermissions?.(user);
            return granted == null ? undefined : permissionSatisfied(granted, ability);
          })();
      if (satisfied === true) return true;
    }
    return (await provider.hasPermission(user, ability, resource)) === true;
  }

  /**
   * Resolve the user's effective roles and test membership against `roles`. Returns
   * `false` for an anonymous (NO_USER) caller and whenever no source yields a role
   * (deny-by-default). Roles come from the UNION of the default/overridden
   * {@link RoleResolver} (reads the user object) and the optional {@link RoleProvider}
   * seam (a persisted store) — so an app needs neither to opt in.
   */
  private async checkRoles(maybeUser: MaybeUser, roles: string[]): Promise<boolean> {
    if (maybeUser === NO_USER || roles.length === 0) return false;
    const userRoles = await this.rolesOf(maybeUser);
    if (userRoles.size === 0) return false;
    return roles.some((r) => userRoles.has(r));
  }

  /** The current user's effective role names (resolver ∪ provider). */
  private async rolesOf(user: User): Promise<Set<string>> {
    const out = new Set<string>();
    const fromResolver = await this.roleResolver(user);
    if (Array.isArray(fromResolver)) {
      for (const r of fromResolver) if (typeof r === 'string') out.add(r);
    }
    const provider = this.resolveRoleProvider();
    if (provider) {
      const fromProvider = await provider.getRoles(user);
      if (Array.isArray(fromProvider)) {
        for (const r of fromProvider) if (typeof r === 'string') out.add(r);
      }
    }
    return out;
  }

  private async check(
    maybeUser: MaybeUser,
    ability: string,
    resource?: Resource,
    cache?: PermissionCache,
  ): Promise<boolean> {
    return (await this.decide(maybeUser, ability, resource, cache)).allowed;
  }

  /**
   * Resolve a decision AND publish it for observers. Returns the full decision
   * (verdict + reason + optional deny message) so {@link authorize} can surface the
   * `reason`/`message` on the thrown `ForbiddenException`. {@link check} discards
   * everything but the verdict.
   */
  private async decide(
    maybeUser: MaybeUser,
    ability: string,
    resource?: Resource,
    cache?: PermissionCache,
  ): Promise<{ allowed: boolean; reason: AuthzDecisionReason; message?: string }> {
    const decision = await this.resolve(maybeUser, ability, resource, cache);
    // Emit the decision for observers (e.g. the generic @dudousxd/nestjs-diagnostics-telescope watcher).
    // Loosely coupled via a diagnostics channel — zero-overhead when no subscriber,
    // and a publish failure can never affect the verdict. Only reached decisions are
    // emitted; an unresolved/ambiguous ability throws above and is intentionally silent.
    publishAuthzDecision(
      ability,
      decision.allowed,
      decision.reason,
      maybeUser === NO_USER ? undefined : maybeUser,
      resource,
    );
    return decision;
  }

  /**
   * Resolve an ability to a final verdict, the path that decided it, and an optional
   * deny message. Runs the global `after` hook over the base decision (see
   * {@link AfterHook} for override semantics). Throws
   * {@link AbilityNotResolvedException}/{@link AmbiguousAbilityException} when no
   * decision can be reached (those paths emit no decision and skip `after`).
   */
  private async resolve(
    maybeUser: MaybeUser,
    ability: string,
    resource?: Resource,
    cache?: PermissionCache,
  ): Promise<{ allowed: boolean; reason: AuthzDecisionReason; message?: string }> {
    const user: User = maybeUser === NO_USER ? undefined : maybeUser;
    const base = await this.resolveBase(maybeUser, ability, resource, cache);

    // Global `after` hook (Laravel `Gate::after`). It may OVERRIDE only when the
    // base path produced no explicit verdict (`base.allowed === undefined`);
    // otherwise it is observe-only. A nullish/void return never changes anything.
    if (this.after) {
      const observed = base.allowed; // undefined ⇒ policy/gate had no opinion
      const after = normalizeResult(await this.after(user, ability, observed, resource));
      if (observed === undefined && after.allowed !== undefined) {
        return withMessage({ allowed: after.allowed, reason: 'after' }, after.message);
      }
    }

    // Finalize: a base with "no opinion" (undefined) denies by default.
    return withMessage({ allowed: base.allowed === true, reason: base.reason }, base.message);
  }

  /**
   * The pre-`after` resolution. `allowed` is `undefined` when the deciding path
   * (policy method / ad-hoc gate) returned a nullish value — "no opinion" — which
   * lets the {@link AfterHook} supply a verdict before the default-deny finalize.
   */
  private async resolveBase(
    maybeUser: MaybeUser,
    ability: string,
    resource?: Resource,
    cache?: PermissionCache,
  ): Promise<{ allowed: boolean | undefined; reason: AuthzDecisionReason; message?: string }> {
    const user: User = maybeUser === NO_USER ? undefined : maybeUser;

    // Global super-admin hook first.
    const sa = normalizeResult(await this.superAdmin?.(user, ability));
    if (sa.allowed === true)
      return withMessage({ allowed: true, reason: 'super-admin' }, sa.message);
    if (sa.allowed === false)
      return withMessage({ allowed: false, reason: 'super-admin' }, sa.message);

    // RBAC seam (Laravel/spatie `Gate::before` grant): if a PermissionProvider is
    // registered and the (authenticated) user holds the named permission, grant it.
    // Grant-only — a `false`/`undefined` result falls through to normal resolution,
    // so this never *denies* an ability a policy/gate would otherwise allow.
    if (
      maybeUser !== NO_USER &&
      (await this.permissionProviderGrants(user, ability, resource, cache))
    ) {
      return { allowed: true, reason: 'permission-provider' };
    }

    const policy = this.resolvePolicy(ability, resource);
    if (policy) {
      const method = (policy as Record<string, unknown>)[ability];
      // The `before` hook may only answer abilities the policy actually defines.
      // Gate it on method existence FIRST so a policy with a `before` but no
      // matching method falls through to AbilityNotResolved instead of letting
      // `before` grant/deny an ability the policy never declared.
      if (typeof method === 'function') {
        const before = (policy as PolicyInstance).before as PolicyBeforeHook | undefined;
        if (typeof before === 'function') {
          const result = normalizeResult(await before.call(policy, user, ability));
          if (result.allowed === true)
            return withMessage({ allowed: true, reason: 'policy-before' }, result.message);
          if (result.allowed === false)
            return withMessage({ allowed: false, reason: 'policy-before' }, result.message);
        }
        // Anonymous users are denied unless a hook granted access above.
        if (maybeUser === NO_USER) return { allowed: false, reason: 'anonymous' };
        const result = normalizeResult(
          (await (method as (...a: unknown[]) => unknown).call(
            policy,
            user,
            resource,
          )) as PolicyResult,
        );
        // A nullish policy return is "no opinion" → leave `allowed` undefined so
        // an `after` hook may decide; otherwise it default-denies in `resolve`.
        return withMessage({ allowed: result.allowed, reason: 'policy' }, result.message);
      }
    }

    // Fall back to an ad-hoc gate.
    const gate = this.gates.get(ability);
    if (gate) {
      if (maybeUser === NO_USER) return { allowed: false, reason: 'anonymous' };
      const result = normalizeResult((await gate(user, resource)) as PolicyResult);
      return withMessage({ allowed: result.allowed, reason: 'gate' }, result.message);
    }

    throw new AbilityNotResolvedException(ability);
  }

  private resolvePolicy(ability: string, resource?: Resource): PolicyInstance | undefined {
    if (resource === undefined) {
      // Class-level ability with no resource: scan registered policies for the
      // method. If MORE THAN ONE policy defines it, picking by Map-insertion
      // order would be a silent, arbitrary (and likely wrong) choice — throw so
      // the caller disambiguates by passing the resource class explicitly.
      const matches = this.policies
        .all()
        .filter((policy) => typeof (policy as Record<string, unknown>)[ability] === 'function');
      if (matches.length === 0) return undefined;
      if (matches.length > 1) {
        throw new AmbiguousAbilityException(
          ability,
          matches.map((p) => (p as PolicyInstance).constructor?.name ?? 'Policy'),
        );
      }
      return matches[0];
    }
    // Resource may be an instance or a class (for class-level abilities passed as Type).
    if (typeof resource === 'function') {
      return this.policies.forResource(resource as Type<unknown>);
    }
    return this.policies.forInstance(resource);
  }
}

/**
 * A {@link Gate} bound to an explicit user. Returned by {@link Gate.forUser}.
 */
export class BoundGate {
  constructor(
    private readonly gate: Gate,
    private readonly user: MaybeUser,
  ) {}

  allows(ability: string, resource?: Resource): Promise<boolean> {
    return this.gate.allowsForUser(this.user, ability, resource);
  }

  async denies(ability: string, resource?: Resource): Promise<boolean> {
    return !(await this.allows(ability, resource));
  }

  /** Batch-authorize many abilities for the bound user in one pass (see {@link Gate.allowsMany}). */
  allowsMany(items: BatchAbility[]): Promise<BatchResult[]> {
    return this.gate.allowsManyForUser(this.user, items);
  }

  /** Resolve the query-scope constraint for the bound user (see {@link Gate.scope}). */
  scope(entity: Type<unknown>, ability = 'viewAny'): Promise<ScopeConstraint> {
    return this.gate.scopeForUser(this.user, entity, ability);
  }

  async authorize(ability: string, resource?: Resource): Promise<void> {
    const decision = await this.gate.decideForUser(this.user, ability, resource);
    if (!decision.allowed) throw forbidden(ability, decision);
  }

  /** True when the bound user holds `role`. */
  hasRole(role: string): Promise<boolean> {
    return this.gate.hasAnyRoleForUser(this.user, [role]);
  }

  /** True when the bound user holds ANY of `roles`. */
  hasAnyRole(roles: string[]): Promise<boolean> {
    return this.gate.hasAnyRoleForUser(this.user, roles);
  }
}
