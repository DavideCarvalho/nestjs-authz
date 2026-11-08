---
"@dudousxd/nestjs-authz": patch
---

`unannotated: 'allow'`: explain the official boot error. `@nestjs/authorization` 0.1.3 recognizes only its
own `AuthorizationGuard` when it checks at startup that each `@Can()` is enforced, so with
`globalGuard: false` it logs "`@Can() is not enforced on …`" for the routes the global `AuthzGuard`
enforces. `AuthzModule` now logs a line right after it that names the same handlers and says the
error is expected in this mode. `AuthzGuard` keeps no official brand on purpose: with it the
official check would report every route this mode lets through as denied. Documented in the
README's migration section.
