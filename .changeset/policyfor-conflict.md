---
"@dudousxd/nestjs-authz": minor
---

`@PolicyFor(Resource)` now throws when `Resource` is already linked to a different policy,
instead of silently replacing the process-wide link. Linking the same pair again stays a
no-op, and a re-declared class of the same name (a test helper declaring its policy per
call, a hot reload) still replaces the link.
