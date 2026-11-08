---
"@dudousxd/nestjs-authz-codegen": minor
---

Abilities of a policy without a `@PolicyFor(Resource)` link are now emitted model-less instead of
under a resource guessed from the class name (`InvoicePolicy` → `Invoice`). The `Gate` (and the
`can()` endpoint) resolves a string ability on a resource only through that link, so the guessed
keys could never resolve. Add `@PolicyFor(Invoice)` to keep the resource key.
