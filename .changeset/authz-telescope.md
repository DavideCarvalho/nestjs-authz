---
"@dudousxd/nestjs-authz-telescope": minor
"@dudousxd/nestjs-authz": patch
---

Add `@dudousxd/nestjs-authz-telescope`: a `@dudousxd/nestjs-telescope` extension that records every
authorization decision the `Gate` reaches (ability, allow/deny, the reason it was decided, the user
and the resource) as an `authorization` Telescope entry plus an "Authorization" dashboard page (a
top-N of denied abilities and a table of recent decisions) — so a 403 is debuggable. The extension's
`AuthorizationWatcher` subscribes to the new `nestjs-authz:decision` diagnostics channel; nothing is
emitted (and nothing recorded) when no observer is listening.

The core `Gate` now publishes each decision on a dependency-free `node:diagnostics_channel`
(`nestjs-authz:decision`, exported as `AUTHZ_DECISION_CHANNEL`) after a verdict is reached. The
emission is gated on `channel.hasSubscribers` and fully guarded, so it is zero-overhead with no
subscriber and can never affect a check. No existing behavior changes.
