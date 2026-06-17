---
'@dudousxd/nestjs-authz': minor
---

Emit authorization decisions on the standard `aviary:authz:decision` channel via
`@dudousxd/nestjs-diagnostics` (`emit('authz', 'decision', payload)`), instead of
the bespoke `nestjs-authz:decision` channel. The decision payload shape
(`AuthzDecisionDiagnostic`, `v: 1`) is unchanged — it now travels inside the
standard envelope (`{ ts, lib, event, traceId?, payload }`), with `traceId`
auto-filled from the optional `@dudousxd/nestjs-context` accessor when present.

Any subscriber that records decisions should now subscribe to
`aviary:authz:decision` and read `envelope.payload`. The generic
`@dudousxd/nestjs-diagnostics-telescope` watcher captures these automatically — no
authz-specific watcher needed.

BREAKING (pre-1.0): the `AUTHZ_DECISION_CHANNEL` constant is removed (the channel
name is now derived via `@dudousxd/nestjs-diagnostics`' `channelName('authz',
'decision')`). The dedicated `@dudousxd/nestjs-authz-telescope` package is retired
in favor of the generic diagnostics watcher.
