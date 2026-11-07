---
"@dudousxd/nestjs-authz": minor
---

Build on NestJS's first-party `@nestjs/authorization` instead of a parallel engine. Requires
NestJS 12, `@nestjs/authorization` ^0.1.3 and Node 22+.

**Use the official API** for policies (`@Policy()`), route checks (`@Can(Policy, 'ability',
args?)`, `Can.Anyone()`), the global deny-by-default `AuthorizationGuard`, the current user
(`getUser`) and `AuthorizationService`. Import `AuthorizationModule.forRoot()` next to
`AuthzModule.forRoot()`.

**Added on top:**

- `RolePolicy` (`has`, `hasAll`) and `PermissionPolicy` (`has`, `hasAll`, wildcards) as
  official policies over the RBAC seams; `GatePolicy` (`allows`) for `gate.define()` gates.
- `@Can()` helpers: `byId(Resource, { param? })` (loads the record with the `ResourceResolver`;
  `authorizedResource(req, Resource)` reads it back), `roles()`, `permission()` /
  `permissions()`, `ability()`, `staticCanArgs()`. Static resolvers carry their args on
  `Symbol.for('@dudousxd/static-can-args')`.
- `@Roles(...)` and `@Permission(...)` sugar that writes official `@Can` metadata.
- `@PolicyFor(Resource)`: links a resource to its official policy (and applies `@Policy()`).
- `AuthzPolicy` base class, `superAdminBefore()` and `decisionProviderBefore()`: the
  `superAdmin` hook and the `DECISION_PROVIDER` (e.g. the Cerbos adapter at
  `@dudousxd/nestjs-authz/cerbos`) for official policies. `superAdmin` receives the resource.
  `RolePolicy` / `PermissionPolicy` ask only `superAdmin`.
- `Gate.allows/denies/authorize(Policy, ability, ...args)` (delegates to `AuthorizationService`)
  next to the string form; `allowsMany` also takes `{ policy, ability, args }`.
- The `authz:decision` channel now also carries the official guard's decisions (allowed and
  denied, `reason: 'route'`, with `policy` and `handler`).
- `PolicyIndex`, `routeRequirements()`, `readCanRequirements()`, `isOfficialPolicy()`,
  `currentUserOf()`.
- The per-request cache (nestjs-context store) now spans the official guard and the handler:
  `RolePolicy` / `PermissionPolicy` and `Gate` calls share one `getPermissions`, one
  `getRoles` and one `resolveUser` per user per request.
- `Gate` calls without `forUser()` read `@nestjs/authentication`'s `AuthenticationContext.user`
  (optional peer, resolved through `ModuleRef`). Inside its scope (a call it handles, or
  `AuthenticationContext.run()`) its answer is final, so an anonymous call is a guest;
  nestjs-context's user ref is read only when there is no authentication scope at all.
- A migration mode, `AuthzModule.forRoot({ unannotated: 'allow' })` (`forRootAsync`: next to
  `useFactory`), for apps that cannot annotate every route at once. With
  `AuthorizationModule.forRoot({ globalGuard: false })`, it registers a global `AuthzGuard` that
  hands every route with `@Can()` requirements to the official `AuthorizationGuard` (same user,
  401/403 and `denied` event) and lets unannotated routes through. The startup fails if the
  official global guard is still on. Default `'deny'`: nothing is registered. `AuthzGuard` is
  exported for `@UseGuards()`.
- `decorators?: ClassDecorator[]`: class decorators applied to every controller the module
  mounts (the `POST /authz/can` endpoint), which are open to the official guard by default
  (`authorization:can-anyone`). `canEndpoint` and `decorators` are static options.

**Removed, with no compatibility shim** (move each to the official form): this package's
`Can` and `Policy` exports and `CanOptions`. The string `@Can('update', Post)` →
`@Can(PostPolicy, 'update', byId(Post))` (`Can` from `@nestjs/authorization`);
`@Can('create', Post, { classLevel: true })` → `@Can(PostPolicy, 'create')`;
`@Can('access-admin')` → `@Can(GatePolicy, 'allows', ability('access-admin'))`;
`@Policy(Post)` → official `@Policy()` + `@PolicyFor(Post)` (or `@PolicyFor(Post)` alone).

**Also removed:** `CanGuard`, `RolesGuard`, `PolicyRegistry` (use `PolicyIndex`), `CAN_METADATA`,
`ROLES_METADATA`, the `policies` and `after` options, deny messages on policy results
(`PolicyResponse` / `PolicyResult` remain only as `DecisionProvider` verdicts),
`PolicyNotDecoratedException`, `ResourceResolverMissingException`, `AfterHook`,
`PolicyMethod`, `PolicyBeforeHook`, `PolicyInstance`.

**The policy has the final word:** string abilities now ask `superAdmin` →
`DECISION_PROVIDER` → the linked policy → the persisted permissions → the ad-hoc gate. A
persisted permission named like a policy ability (`update`) no longer bypasses the policy, in
checks and in `gate.scope()`; only `superAdmin` does. Permissions still grant named abilities
no policy defines (`posts.publish`).

**Behavior changes from the official guard:** routes with no `@Can()` are denied (add
`@Can.Anyone()`, or migrate with `unannotated: 'allow'`); class- and method-level requirements add up; guests reach policies as
`null` and are answered 401; only a literal `true` allows; `superAdmin` applies to policies
that extend `AuthzPolicy` (and to the built-in ones, string `Gate` checks and `gate.scope`).
`gate.hasRole()` stays a plain fact (no `superAdmin`); `RolePolicy` honors it. A
`DecisionProvider` and `superAdmin` see a guest as `null` (was `undefined`).
