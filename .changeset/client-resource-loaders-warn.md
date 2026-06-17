---
"@dudousxd/nestjs-authz-client": patch
---

Soften the resource-bound fetch-fallback `console.warn` and docstrings: a per-instance
`can(ability, { type, id })` cache miss under `fallback: 'fetch'` now resolves on the server
when the app registered a matching `resourceLoaders` entry for that `type` (core feature) —
it only denies when neither tier-1/2 hydration nor a loader covers it.
