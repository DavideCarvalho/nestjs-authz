import type { Type } from '@nestjs/common';
import type { ScopeConstraint } from './scope.js';
import type { PolicyResult, Resource, User } from './types.js';

/**
 * What a {@link DecisionProvider} answers for one `(user, ability, resource)`:
 *
 * - `true` / `{ allowed: true }` → **allow** (short-circuits the Gate);
 * - `false` / `{ allowed: false, message? }` → **deny** (short-circuits the Gate — unlike the
 *   grant-only {@link PermissionProvider}, a decision provider CAN deny);
 * - `undefined` / `null` → **abstain**: the provider has no opinion (e.g. the resource kind or
 *   the tenant isn't governed by the external engine) and the Gate continues with its normal
 *   resolution (permission provider → policy → ad-hoc gate).
 */
export type DecisionVerdict = PolicyResult | undefined;

/** One `(ability, resource)` pair in a {@link DecisionProvider.decideMany} batch. */
export interface DecisionRequest {
  ability: string;
  resource?: Resource;
}

/**
 * Optional seam for an **external policy decision point** (Cerbos, OPA, OpenFGA, a remote
 * authz service, …) — the authoritative, resource-aware counterpart of the grant-only
 * {@link PermissionProvider}. Register it under the {@link DECISION_PROVIDER} token.
 *
 * ## Precedence (single decision)
 *
 * 1. global `superAdmin` hook (receives the resource as 3rd argument) — allow/deny short-circuit;
 * 2. **decision provider** `decide` — allow/deny short-circuit, `undefined` abstains;
 * 3. permission provider grant (RBAC, grant-only);
 * 4. policy `before` → policy method, else ad-hoc gate;
 * 5. global `after` hook (only when the path above had no opinion).
 *
 * The provider is also consulted for anonymous callers (`user` is `undefined`) so an engine can
 * allow public access; abstain to keep the Gate's default anonymous-deny.
 *
 * ## Batching
 *
 * `gate.allowsMany(...)` calls {@link decideMany} ONCE for the whole batch when implemented (a
 * list page with N cards costs one engine round-trip instead of N); otherwise `decide` per item.
 *
 * ## Query scopes
 *
 * `gate.scope(Entity, ability)` calls {@link planScope} right after the `superAdmin` hook. A
 * returned {@link ScopeConstraint} is used as-is (e.g. an engine's query plan mapped onto the scope
 * AST — see `@dudousxd/nestjs-authz/cerbos`); `undefined` abstains and the Gate falls back to the
 * permission-provider grant / the policy's `scope` method.
 *
 * Errors thrown by the provider propagate (the check fails loudly). Providers that talk to a
 * remote engine should decide their own failure mode — the Cerbos adapter fails CLOSED (deny).
 */
export interface DecisionProvider {
  decide(
    user: User,
    ability: string,
    resource?: Resource,
  ): DecisionVerdict | Promise<DecisionVerdict>;
  /** Optional batch form; must return one verdict per request, in order. */
  decideMany?(user: User, requests: DecisionRequest[]): Promise<DecisionVerdict[]>;
  /** Optional query-plan → scope mapping. `undefined` = abstain. */
  planScope?(
    user: User,
    entity: Type<unknown>,
    ability: string,
  ): ScopeConstraint | undefined | Promise<ScopeConstraint | undefined>;
}
