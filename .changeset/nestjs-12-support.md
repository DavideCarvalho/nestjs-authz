---
"@dudousxd/nestjs-authz": patch
"@dudousxd/nestjs-authz-inertia": patch
"@dudousxd/nestjs-authz-mikro-orm": patch
"@dudousxd/nestjs-authz-prisma": patch
"@dudousxd/nestjs-authz-typeorm": patch
---

Support NestJS 12.

The `@nestjs/common` / `@nestjs/core` peer ranges are already `>=10.0.0`, so they
admit 12 unchanged. The dev/test matrix now runs on `@nestjs/*@12.0.1` (and the
MikroORM 7 integration app with it), so v12 is covered by CI rather than merely
allowed by the range. No source changes were needed.
