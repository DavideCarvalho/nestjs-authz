---
"@dudousxd/nestjs-authz": patch
"@dudousxd/nestjs-authz-mikro-orm": patch
"@dudousxd/nestjs-authz-prisma": patch
"@dudousxd/nestjs-authz-typeorm": patch
---

Internal refactors (behavior-preserving): single-source the ORM store contract (`UserRef`/`UserRefInput`/`UserAuthz`/`normalizeUserRef`) via a new `@dudousxd/nestjs-authz/store-kit` subpath that the typeorm/prisma/mikro-orm adapters re-export under their public names, so the definition can't drift across them. Also single-source the grant preamble and the SQL identifier guard in the core store path.
