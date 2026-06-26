# Skill spec — @dudousxd/nestjs-authz

Autonomous discovery pass (no maintainer interview — interview phases skipped per
orchestrator rules). Source of truth: repo source under `packages/core/src`, the root
`README.md`, and `DESIGN.md`.

## Scope decision

Primary client-facing package: **`@dudousxd/nestjs-authz`** (`packages/core`). This is
the main NestJS module every consumer imports. The 8-package monorepo also ships 3
parallel ORM RBAC adapters (typeorm/prisma/mikro-orm) and 4 client-side packages
(client/codegen/react/inertia) plus a testing helper — all left uncovered this pass to
keep a focused, correct set and avoid an arbitrary ORM pick. See `domain_map.yaml`
`secondary_uncovered` + `gaps`.

Flat structure: `packages/core/skills/<skill>/SKILL.md`. 5 skills, all `type: core`
(no router needed under the <5/flat heuristic; 5 is the boundary and these are
non-hierarchical peers).

## Skills

1. **authz-setup** — install, peer deps, `AuthzModule.forRoot`/`forRootAsync`, the
   nestjs-context optional peer, and the load-bearing `resolveUser` gotcha
   (UserRef vs hydrated entity). The single most important correctness trap.
2. **authz-policies** — `@Policy(Resource)` classes, ability methods, the `before`
   hook short-circuit, deny messages via `PolicyResponse`, global `superAdmin`/`after`
   hooks and their override semantics.
3. **authz-enforcement** — `@Can` (instance / classLevel / ad-hoc) + `@Roles` guards,
   the `ResourceResolver` seam (default `IdParamResourceResolver` vs a real ORM one),
   and the programmatic `Gate` API (`authorize`/`allows`/`forUser`/`allowsMany`/`define`).
4. **authz-query-scopes** — `gate.scope(Entity, ability)` and the ORM-neutral
   `ScopeConstraint` AST (`scopeAll`/`scopeNone`/`where`/`eq`/`and`/`or`), a `@Policy`
   `scope` method, and how an adapter (`applyScope`) compiles it to a WHERE.
5. **authz-rbac-seams** — the optional `PERMISSION_PROVIDER` / `ROLE_PROVIDER` seams,
   wildcard permission matching (`getPermissions`), `defaultRoleResolver`, and wiring a
   persisted adapter (`AuthzRbacModule`) so the Gate consults persisted roles/permissions.

## Common-mistake themes mined from source

- Trusting `superAdmin: u => u.isAdmin` on the context path without `resolveUser` — fires
  against `{type,id}`, never sees `isAdmin`. (types.ts warns about this explicitly.)
- Expecting a class-level `@Can('create', Post)` to load an instance — it must pass
  `{ classLevel: true }` or the guard tries to resolve a resource.
- Returning nothing from a policy method and expecting allow — nullish = "no opinion" =
  default-deny.
- Using `@Can('create', Post)` for a class-level ability registered on MULTIPLE policies
  without a resource → `AmbiguousAbilityException`.
- Concatenating identifiers into scope queries instead of using `where`/`eq` builders
  (values are bound; identifiers validated by `SAFE_IDENTIFIER`).
- Expecting the `after` hook to override an explicit policy verdict — it can only fill in
  when the policy/gate returned nullish.
- Forgetting that the RBAC seam is grant-only: a `PermissionProvider` returning `false`
  never DENIES, it falls through.

## Remaining Gaps (interview substitute)

See `domain_map.yaml` `gaps:` — reproduced intent: external docs site not fetched; no
GitHub issue mining; ORM-adapter coverage deliberately deferred; production default usage
(canEndpoint/resourceLoaders/hydration) unconfirmed; stable-version/compat range guessed
from package.json (0.6.3, alpha line). All code in the SKILL.md files is grounded in real
exported symbols from `packages/core/src`.
