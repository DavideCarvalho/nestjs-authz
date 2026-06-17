---
"@dudousxd/nestjs-authz": patch
---

perf: memoize per-check work in the authorization path — cache the three `ModuleRef` seam resolutions (permission/context/role) so the `strict: false` container scan runs at most once per seam instead of per check, and cache `PolicyRegistry.classAbilities()` (invalidated on `register()`).
