---
"@dudousxd/nestjs-authz": patch
---

Derive authz's own DI tokens (`AUTHZ_MODULE_OPTIONS`, `RESOURCE_RESOLVER`, `RESOURCE_HYDRATOR`, `PERMISSION_PROVIDER`, `ROLE_PROVIDER`) from the `capability()` factory instead of hand-rolled `Symbol.for` strings, and add a conformance test (`assertCapabilityNaming`) that locks their canonical naming. Resolves to byte-identical symbols — fully non-breaking.
