---
"@dudousxd/nestjs-authz": patch
---

A `Gate` string check that reaches a linked `AuthzPolicy` now asks `superAdmin` and the
`DECISION_PROVIDER` once, not again in the policy's `before()`. Same decision order and verdicts.
