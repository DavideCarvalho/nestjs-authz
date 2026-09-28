---
'@dudousxd/nestjs-authz': minor
---

External policy engines: a new `DecisionProvider` seam (`DECISION_PROVIDER` token) and a Cerbos adapter at `@dudousxd/nestjs-authz/cerbos`.

- `DecisionProvider.decide(user, ability, resource)` can **allow, deny or abstain**. It runs right after the `superAdmin` hook and before the permission provider, the policy `before` hook, policies and gates. `authorize()` surfaces denials with reason `decision-provider`. It is also consulted for anonymous callers.
- Optional `decideMany` batches `gate.allowsMany` into one engine round-trip. If the batch call fails, each item falls back to its own `decide` call.
- Optional `planScope(user, Entity, ability)` feeds `gate.scope()` right after `superAdmin`. Returning `undefined` abstains and falls back to the permission provider or policy scope.
- The `superAdmin` hook now receives the resource as a third argument: the checked resource, or the entity class for `gate.scope()`. This is additive.
- `@dudousxd/nestjs-authz/cerbos`:
  - `CerbosDecisionProvider` supports per-user/per-tenant clients, batching with de-duplication and chunking, and fails closed by default.
  - `cerbosPlanToScope` maps Cerbos `PlanResources` onto the scope AST: and/or, `not` via De Morgan, eq/ne/lt/gt/le/ge/in, and null checks. Anything else is rejected, which fails closed.
  - Client types are structural, so the package has no runtime dependency on the Cerbos SDKs.
