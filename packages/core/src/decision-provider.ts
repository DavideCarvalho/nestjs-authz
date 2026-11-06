import type { Type } from '@nestjs/common';
import type { ScopeConstraint } from './scope.js';
import type { PolicyResult, Resource, User } from './types.js';

/**
 * What a {@link DecisionProvider} answers for one `(user, ability, resource)`:
 *
 * - `true` / `{ allowed: true }` → **allow** (short-circuits);
 * - `false` / `{ allowed: false, message? }` → **deny** (short-circuits — unlike the
 *   grant-only {@link PermissionProvider}, a decision provider CAN deny);
 * - `undefined` / `null` → **abstain**: the provider has no opinion (e.g. the resource kind or
 *   the tenant isn't governed by the external engine) and resolution continues as usual.
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
 * ## Where it is asked
 *
 * Right after the global `superAdmin` hook (which receives the resource too), everywhere a
 * decision is made:
 *
 * - **routes**: the official guard runs each policy's `before()`. Policies extending
 *   `AuthzPolicy` ask `superAdmin`, then `decide(user, ability, firstArg)`. `RolePolicy` and
 *   `PermissionPolicy` do not ask it: their abilities (`has`, `hasAll`) name no resource.
 * - **`gate.allows(ability, resource)`**: before the linked policy, the persisted
 *   permissions and the ad-hoc gate.
 * - **`gate.allows(PostPolicy, 'update', post)`**: through the policy's `before()`, as above.
 *
 * The provider is also consulted for guests (`user` is `null`) so an engine can allow public
 * access; abstain to keep the default guest-deny.
 *
 * ## Batching
 *
 * `gate.allowsMany(...)` calls {@link decideMany} ONCE for the string abilities of the batch
 * when implemented (a list page with N cards costs one engine round-trip instead of N);
 * otherwise `decide` per item.
 *
 * ## Query scopes
 *
 * `gate.scope(Entity, ability)` calls {@link planScope} right after the `superAdmin` hook. A
 * returned {@link ScopeConstraint} is used as-is (e.g. an engine's query plan mapped onto the scope
 * AST — see `@dudousxd/nestjs-authz/cerbos`); `undefined` abstains and the policy's `scope`
 * method decides.
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

/** A verdict as `{ allowed, message }`; `allowed` is `undefined` when the provider abstains. */
export function normalizeVerdict(verdict: DecisionVerdict | null): {
  allowed: boolean | undefined;
  message?: string;
} {
  if (verdict === true || verdict === false) return { allowed: verdict };
  if (verdict && typeof verdict === 'object' && typeof verdict.allowed === 'boolean') {
    return verdict.message === undefined
      ? { allowed: verdict.allowed }
      : { allowed: verdict.allowed, message: verdict.message };
  }
  return { allowed: undefined };
}
