---
"@dudousxd/nestjs-authz": patch
---

`PolicyIndex` no longer freezes its first discovery scan: it rescans when a module or provider
is added (a lazy module) or a policy was not instantiated yet, so `resourcePolicies()`,
`classAbilities()` (the Inertia ability map) and `gate.scope()` see the same policies.
