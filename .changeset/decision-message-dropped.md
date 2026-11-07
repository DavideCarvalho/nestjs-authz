---
"@dudousxd/nestjs-authz": patch
---

Document that a `DecisionProvider` deny `message` no longer reaches the 403 in 0.9. The official
guard answers `{ statusCode: 403, message: 'Forbidden' }`, and `@nestjs/authorization` has no
deny-with-reason. Added to the 0.8 → 0.9 migration table, with the workaround and what it costs.
`PolicyResponse`'s doc comment no longer claims the message is published on the decision event.
