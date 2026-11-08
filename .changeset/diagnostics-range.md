---
"@dudousxd/nestjs-authz": patch
---

Depend on `@dudousxd/nestjs-diagnostics` `>=0.7.0 <1.0.0` instead of the exact `0.7.1`, so an app on diagnostics 0.8.0 shares one copy (and one channel and capability registry) instead of installing a second one.
