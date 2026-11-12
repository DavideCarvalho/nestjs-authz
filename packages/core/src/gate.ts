import { type Ability, AuthorizationError, AuthorizationService } from '@nestjs/authorization';
import { Inject, Injectable, Optional, type Type } from '@nestjs/common';
import { type DecisionVerdict, normalizeVerdict } from './decision-provider.js';
import { type AuthzDecisionReason, publishAuthzDecision } from './diagnostics.js';
import { AbilityNotResolvedException, AmbiguousAbilityException } from './errors/exceptions.js';
import { isOfficialPolicy, requireOfficial } from './official.js';
import { PermissionCache } from './permission-cache.js';
import { withAskedCheck } from './policies/authz-policy.js';
import { PolicyIndex } from './policy-index.js';
import { AuthzRbac } from './rbac.js';
import {
  type ScopeConstraint,
  type ScopeMethod,
  normalizeScope,
  scopeAll,
  scopeNone,
} from './scope.js';
import { AUTHZ_MODULE_OPTIONS } from './tokens.js';
import type { AuthzModuleOptions, GateFn, Resource, SuperAdminHook, User } from './types.js';

/** The arguments after the user of ability `A` on policy `P`. */
export type AbilityArgsOf<P, A extends keyof P> = P[A] extends (
  user: never,
  ...args: infer R
) => unknown
  ? R
  : never;

/** A string ability, optionally on a resource (instance, or class for class-level abilities). */
export interface BatchAbility {
  ability: string;
  resource?: Resource;
}

/** An official policy check: `policy[ability](user, ...args)`. */
export interface BatchPolicyCheck {
  policy: Type<unknown>;
  ability: string;
  args?: readonly unknown[];
}

/** One item of a {@link Gate.allowsMany} batch. */
export type BatchItem = BatchAbility | BatchPolicyCheck;

/** One result of a {@link Gate.allowsMany} batch: the item plus its verdict. */
export type BatchResult = BatchItem & { allowed: boolean };

interface Decision {
  allowed: boolean;
  reason: AuthzDecisionReason;
  policy: string | null;
  /** The decision provider's reason, when it gave one. */
  message?: string;
}

/** What {@link Gate.explainFor} answers. */
export interface GateExplanation {
  allowed: boolean;
  /** The resolution path that decided, or `'unresolved'` when nothing defines the ability. */
  reason: AuthzDecisionReason | 'unresolved';
  /** The policy class that decided, or `null`. */
  policy: string | null;
  /** The decision provider's message, or the error when the ability could not be resolved. */
  message?: string;
  /** `superAdmin` granted it. */
  superAdmin: boolean;
  /** What the external decision point said; `'none'` without one. */
  decisionProvider: 'none' | 'not-consulted' | 'allowed' | 'denied' | 'abstained';
}

/** A verdict the external decision point already gave for a batch item. */
interface Prefetched {
  verdict: DecisionVerdict;
}

const isPolicyCheck = (item: BatchItem): item is BatchPolicyCheck =>
  typeof (item as BatchPolicyCheck).policy === 'function';

/**
 * A façade over the official `AuthorizationService` for service-layer checks, with what
 * the official service does not have:
 *
 * - **string abilities**, Laravel-style: `gate.allows('update', post)` finds the policy
 *   linked to `Post` with `@PolicyFor(Post)`; `gate.allows('access-admin')` runs an
 *   ad-hoc gate from {@link define}; `gate.allows('posts.publish')` asks the persisted
 *   permissions. Asks `superAdmin` first, then the external decision point
 *   (`DECISION_PROVIDER`), then the policy — which has the final word: a persisted
 *   permission named like the ability does not bypass it — then the persisted
 *   permissions, then the ad-hoc gate.
 * - **official policy checks**: `gate.allows(PostPolicy, 'update', post)`, exactly
 *   `AuthorizationService.can()`.
 * - **batches** ({@link allowsMany}) sharing one permission fetch, **query scopes**
 *   ({@link scope}), **roles** ({@link hasRole}), an allow+deny decision event, and an
 *   ambient user when none is passed ({@link forUser} passes one): `@nestjs/authentication`'s
 *   `AuthenticationContext.user` when that package is installed, else nestjs-context's.
 *
 * Every policy decision is the official service's: the policy's own `before()`, then
 * the ability, allowed only on a literal `true`.
 */
@Injectable()
export class Gate {
  private readonly gates = new Map<string, GateFn>();
  private readonly superAdmin: SuperAdminHook | undefined;
  private readonly authz: AuthorizationService;

  constructor(
    @Optional() @Inject(AuthorizationService) authz: AuthorizationService | undefined,
    private readonly index: PolicyIndex,
    private readonly rbac: AuthzRbac,
    @Optional() @Inject(AUTHZ_MODULE_OPTIONS) options?: AuthzModuleOptions,
  ) {
    this.authz = requireOfficial(authz, 'AuthorizationService', 'Gate');
    this.superAdmin = options?.superAdmin;
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

  /** Names of every ad-hoc gate registered with {@link define}. */
  gateNames(): string[] {
    return [...this.gates.keys()];
  }

  /**
   * Bind an explicit user. `null`/`undefined` is a guest. The usual way to check in a
   * service: pass the user your handler received.
   */
  forUser(user: User): BoundGate {
    return new BoundGate(this, user ?? null);
  }

  /**
   * The ambient user, for calls without {@link forUser}: `@nestjs/authentication`'s
   * `AuthenticationContext.user` when that optional peer is installed and has one, else
   * nestjs-context's user ref (hydrated by `resolveUser` when configured, once per
   * request). `null` without either.
   */
  private currentUser(): Promise<User> {
    return this.rbac.currentUser();
  }

  // --- current (ambient) user ---

  allows<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    ...args: AbilityArgsOf<P, A>
  ): Promise<boolean>;
  allows(ability: string, resource?: Resource): Promise<boolean>;
  async allows(first: string | Type<unknown>, ...rest: unknown[]): Promise<boolean> {
    return this.allowsFor(await this.currentUser(), first, rest);
  }

  denies<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    ...args: AbilityArgsOf<P, A>
  ): Promise<boolean>;
  denies(ability: string, resource?: Resource): Promise<boolean>;
  async denies(first: string | Type<unknown>, ...rest: unknown[]): Promise<boolean> {
    return !(await this.allowsFor(await this.currentUser(), first, rest));
  }

  /**
   * Like {@link allows}, but throws the official `AuthorizationError` on a denial, which
   * the official module turns into a 401/403 (or the transport's error) when it leaves
   * a handler.
   */
  authorize<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    ...args: AbilityArgsOf<P, A>
  ): Promise<void>;
  authorize(ability: string, resource?: Resource): Promise<void>;
  async authorize(first: string | Type<unknown>, ...rest: unknown[]): Promise<void> {
    return this.authorizeFor(await this.currentUser(), first, rest);
  }

  /** Check many abilities at once (one user, one permission fetch). A failing item denies. */
  async allowsMany(items: readonly BatchItem[]): Promise<BatchResult[]> {
    return this.allowsManyFor(await this.currentUser(), items);
  }

  /**
   * The query scope of `entity` (a resource class linked with `@PolicyFor`, or the
   * policy class itself) for the current user, from the policy's `scope(user, entity)`
   * method (else the `ability` method, `viewAny` by default). See {@link ScopeConstraint}.
   */
  async scope(entity: Type<unknown>, ability = 'viewAny'): Promise<ScopeConstraint> {
    return this.scopeFor(await this.currentUser(), entity, ability);
  }

  /** True when the current user holds `role` (a fact: `superAdmin` does not apply). */
  async hasRole(role: string): Promise<boolean> {
    return this.rbac.hasAnyRole(await this.currentUser(), [role]);
  }

  /** True when the current user holds any of `roles`. */
  async hasAnyRole(roles: string[]): Promise<boolean> {
    return this.rbac.hasAnyRole(await this.currentUser(), roles);
  }

  // --- explicit user (BoundGate) ---

  /** @internal */
  async allowsFor(user: User, first: string | Type<unknown>, rest: unknown[]): Promise<boolean> {
    return (await this.decide(user, first, rest, this.rbac.requestCache(), false)).allowed;
  }

  /** @internal */
  async authorizeFor(user: User, first: string | Type<unknown>, rest: unknown[]): Promise<void> {
    const decision = await this.decide(user, first, rest, this.rbac.requestCache(), true);
    if (!decision.allowed) {
      throw new AuthorizationError(
        user == null ? 'unauthenticated' : 'forbidden',
        decision.policy,
        typeof first === 'string' ? first : String(rest[0]),
      );
    }
  }

  /** @internal */
  async allowsManyFor(user: User, items: readonly BatchItem[]): Promise<BatchResult[]> {
    const cache = this.rbac.requestCache() ?? new PermissionCache();
    const prefetched = await this.prefetchDecisions(user, items);
    const out: BatchResult[] = [];
    for (const [index, item] of items.entries()) {
      let allowed: boolean;
      try {
        const [first, rest] = isPolicyCheck(item)
          ? [item.policy, [item.ability, ...(item.args ?? [])]]
          : [item.ability, item.resource === undefined ? [] : [item.resource]];
        allowed = (await this.decide(user, first, rest, cache, false, prefetched.get(index)))
          .allowed;
      } catch {
        allowed = false;
      }
      out.push({ ...item, allowed });
    }
    return out;
  }

  /**
   * One `decideMany` round-trip to the external decision point for the string abilities
   * of a batch, when it supports batching. Empty otherwise, and when the batch call fails
   * (each item then asks `decide` on its own).
   */
  private async prefetchDecisions(
    user: User,
    items: readonly BatchItem[],
  ): Promise<Map<number, Prefetched>> {
    const out = new Map<number, Prefetched>();
    const provider = this.rbac.decisions();
    if (!provider || typeof provider.decideMany !== 'function') return out;
    const indexes: number[] = [];
    const requests: Array<{ ability: string; resource?: Resource }> = [];
    for (const [index, item] of items.entries()) {
      if (isPolicyCheck(item)) continue;
      indexes.push(index);
      requests.push(
        item.resource === undefined
          ? { ability: item.ability }
          : { ability: item.ability, resource: item.resource },
      );
    }
    if (requests.length === 0) return out;
    try {
      const verdicts = await provider.decideMany(user, requests);
      if (!Array.isArray(verdicts) || verdicts.length !== requests.length) return out;
      for (const [i, index] of indexes.entries()) out.set(index, { verdict: verdicts[i] });
    } catch {
      out.clear();
    }
    return out;
  }

  /**
   * How a string ability check for `user` is decided, step by step, with no decision event
   * published: the `authz_explain_check` dev tool. `cache` defaults to a fresh one, so the
   * answer never reuses the request's fetches. An ability nothing defines answers
   * `{ allowed: false, reason: 'unresolved' }` instead of throwing.
   */
  async explainFor(
    user: User,
    ability: string,
    resource?: Resource,
    cache: PermissionCache = new PermissionCache(),
  ): Promise<GateExplanation> {
    let decision: Omit<Decision, 'reason'> & { reason: GateExplanation['reason'] };
    try {
      decision = await this.decideString(user, ability, resource, cache, false, undefined);
    } catch (error) {
      const unresolved =
        error instanceof AbilityNotResolvedException || error instanceof AmbiguousAbilityException;
      if (!unresolved) throw error;
      decision = { allowed: false, reason: 'unresolved', policy: null, message: error.message };
    }
    const superAdmin = decision.reason === 'super-admin';
    let decisionProvider: GateExplanation['decisionProvider'] = 'none';
    if (this.rbac.decisions()) {
      if (superAdmin) decisionProvider = 'not-consulted';
      else if (decision.reason === 'decision-provider')
        decisionProvider = decision.allowed ? 'allowed' : 'denied';
      else decisionProvider = 'abstained';
    }
    return {
      allowed: decision.allowed,
      reason: decision.reason,
      policy: decision.policy,
      ...(decision.message !== undefined ? { message: decision.message } : {}),
      superAdmin: superAdmin && decision.allowed,
      decisionProvider,
    };
  }

  /** @internal */
  async hasAnyRoleFor(user: User, roles: string[]): Promise<boolean> {
    return this.rbac.hasAnyRole(user, roles);
  }

  /** @internal */
  async scopeFor(user: User, entity: Type<unknown>, ability: string): Promise<ScopeConstraint> {
    if ((await this.superAdmin?.(user, ability, entity)) === true) return scopeAll;

    // The external decision point's query plan (e.g. Cerbos PlanResources), used as-is.
    const planner = this.rbac.decisions();
    if (planner && typeof planner.planScope === 'function') {
      const planned = await planner.planScope(user, entity, ability);
      if (planned !== undefined) return planned;
    }

    // The policy has the final word; a persisted permission only scopes an entity
    // without a policy method to ask.
    const policy = isOfficialPolicy(entity) ? entity : this.index.policyFor(entity);
    const instance = policy
      ? (this.index.instanceOf(policy) as Record<string, unknown>)
      : undefined;
    const method = (
      instance && typeof instance.scope === 'function' ? instance.scope : instance?.[ability]
    ) as ScopeMethod | undefined;
    if (!instance || typeof method !== 'function') {
      return (await this.rbac.grants(user, ability)) ? scopeAll : scopeNone;
    }

    const before = instance.before as ((user: User, ability: string) => unknown) | undefined;
    if (typeof before === 'function') {
      const early = await before.call(instance, user ?? null, ability);
      if (early === true) return scopeAll;
      if (early === false) return scopeNone;
    }
    if (user == null) return scopeNone;
    return normalizeScope(await method.call(instance, user, entity));
  }

  // --- resolution ---

  /** Decide, publish the decision, and (in `authorize` mode) let the official service emit its denial. */
  private async decide(
    user: User,
    first: string | Type<unknown>,
    rest: unknown[],
    cache: PermissionCache | undefined,
    authorizing: boolean,
    prefetched?: Prefetched,
  ): Promise<Decision> {
    const ability = typeof first === 'string' ? first : String(rest[0]);
    const resource =
      typeof first === 'string'
        ? (rest[0] as Resource | undefined)
        : (rest[1] as Resource | undefined);
    const decision =
      typeof first === 'string'
        ? await this.decideString(user, first, resource, cache, authorizing, prefetched)
        : await this.decidePolicy(user, first, ability, rest.slice(1), authorizing);
    publishAuthzDecision(ability, decision.allowed, decision.reason, user, resource, {
      policy: decision.policy,
    });
    return decision;
  }

  private async decidePolicy(
    user: User,
    policy: Type<unknown>,
    ability: string,
    args: unknown[],
    authorizing: boolean,
  ): Promise<Decision> {
    const service = this.authz as unknown as {
      can(p: Type<unknown>, a: string, u: User, ...args: unknown[]): Promise<boolean>;
      authorize(p: Type<unknown>, a: string, u: User, ...args: unknown[]): Promise<void>;
    };
    let allowed: boolean;
    if (authorizing) {
      try {
        await service.authorize(policy, ability, user, ...args);
        allowed = true;
      } catch (error) {
        if (!(error instanceof AuthorizationError)) throw error;
        allowed = false;
      }
    } else {
      allowed = await service.can(policy, ability, user, ...args);
    }
    return { allowed, reason: 'policy', policy: policy.name };
  }

  private async decideString(
    user: User,
    ability: string,
    resource: Resource | undefined,
    cache: PermissionCache | undefined,
    authorizing: boolean,
    prefetched: Prefetched | undefined,
  ): Promise<Decision> {
    if ((await this.superAdmin?.(user, ability, resource)) === true) {
      return { allowed: true, reason: 'super-admin', policy: null };
    }

    // External decision point (Cerbos/OPA/...): its allow or deny is final; `undefined` abstains.
    const provider = this.rbac.decisions();
    if (provider) {
      const verdict = normalizeVerdict(
        prefetched ? prefetched.verdict : await provider.decide(user, ability, resource),
      );
      if (verdict.allowed !== undefined) {
        return verdict.message === undefined
          ? { allowed: verdict.allowed, reason: 'decision-provider', policy: null }
          : {
              allowed: verdict.allowed,
              reason: 'decision-provider',
              policy: null,
              message: verdict.message,
            };
      }
    }

    // A policy that defines the ability has the final word: a persisted permission
    // named like the ability does not bypass it.
    const policy = this.policyFor(ability, resource);
    if (policy) {
      const args = resource !== undefined && typeof resource !== 'function' ? [resource] : [];
      // superAdmin and the decision point were asked above: an `AuthzPolicy` `before()`
      // must not ask them again for this same check.
      return withAskedCheck(user, ability, args, () =>
        this.decidePolicy(user, policy, ability, args, authorizing),
      );
    }

    if (await this.rbac.grants(user, ability, resource, cache)) {
      return { allowed: true, reason: 'permission-provider', policy: null };
    }

    const gate = this.gates.get(ability);
    if (gate) {
      if (user == null) return { allowed: false, reason: 'anonymous', policy: null };
      return { allowed: (await gate(user, resource)) === true, reason: 'gate', policy: null };
    }

    throw new AbilityNotResolvedException(ability);
  }

  /** The linked policy defining `ability` for `resource` (or for no resource, unambiguously). */
  private policyFor(ability: string, resource: Resource | undefined): Type<unknown> | undefined {
    if (resource === undefined) {
      const matches = this.index.linkedPoliciesWith(ability);
      if (matches.length > 1) {
        throw new AmbiguousAbilityException(
          ability,
          matches.map((p) => p.name),
        );
      }
      return matches[0];
    }
    const policy = this.index.policyOf(resource);
    if (!policy) return undefined;
    return typeof (policy.prototype as Record<string, unknown>)[ability] === 'function'
      ? policy
      : undefined;
  }
}

/** A {@link Gate} bound to an explicit user. Returned by {@link Gate.forUser}. */
export class BoundGate {
  constructor(
    private readonly gate: Gate,
    private readonly user: User,
  ) {}

  allows<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    ...args: AbilityArgsOf<P, A>
  ): Promise<boolean>;
  allows(ability: string, resource?: Resource): Promise<boolean>;
  allows(first: string | Type<unknown>, ...rest: unknown[]): Promise<boolean> {
    return this.gate.allowsFor(this.user, first, rest);
  }

  denies<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    ...args: AbilityArgsOf<P, A>
  ): Promise<boolean>;
  denies(ability: string, resource?: Resource): Promise<boolean>;
  async denies(first: string | Type<unknown>, ...rest: unknown[]): Promise<boolean> {
    return !(await this.gate.allowsFor(this.user, first, rest));
  }

  authorize<P, const A extends Ability<P>>(
    policy: Type<P>,
    ability: A,
    ...args: AbilityArgsOf<P, A>
  ): Promise<void>;
  authorize(ability: string, resource?: Resource): Promise<void>;
  authorize(first: string | Type<unknown>, ...rest: unknown[]): Promise<void> {
    return this.gate.authorizeFor(this.user, first, rest);
  }

  /** Batch-check for the bound user (see {@link Gate.allowsMany}). */
  allowsMany(items: readonly BatchItem[]): Promise<BatchResult[]> {
    return this.gate.allowsManyFor(this.user, items);
  }

  /** The query scope for the bound user (see {@link Gate.scope}). */
  scope(entity: Type<unknown>, ability = 'viewAny'): Promise<ScopeConstraint> {
    return this.gate.scopeFor(this.user, entity, ability);
  }

  hasRole(role: string): Promise<boolean> {
    return this.gate.hasAnyRoleFor(this.user, [role]);
  }

  hasAnyRole(roles: string[]): Promise<boolean> {
    return this.gate.hasAnyRoleFor(this.user, roles);
  }
}
