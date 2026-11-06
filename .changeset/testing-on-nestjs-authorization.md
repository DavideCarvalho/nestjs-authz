---
"@dudousxd/nestjs-authz-testing": major
---

`buildGate` / `buildBoundGate` are async and compile a Nest testing module with the official
`AuthorizationModule` and `AuthzModule`, so decisions run through `AuthorizationService`.
`policies` takes classes (or providers) instead of instances; the `after` option is gone. New:
`createAuthzTestingModule()`, official-style `expectCan(gate, user, Policy, 'ability', ...args)`,
and `requirementsOf(Controller, 'method')`. Peers on `@nestjs/authorization`,
`@nestjs/common`/`core`/`testing` 12.
