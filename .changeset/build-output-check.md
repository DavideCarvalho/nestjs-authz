---
"@dudousxd/nestjs-authz-client": patch
"@dudousxd/nestjs-authz-codegen": patch
"@dudousxd/nestjs-authz": patch
"@dudousxd/nestjs-authz-drizzle": patch
"@dudousxd/nestjs-authz-inertia": patch
"@dudousxd/nestjs-authz-mikro-orm": patch
"@dudousxd/nestjs-authz-prisma": patch
"@dudousxd/nestjs-authz-react": patch
"@dudousxd/nestjs-authz-testing": patch
"@dudousxd/nestjs-authz-typeorm": patch
---

Fix packages that could be published without files their `exports` point to. `tsc` builds no longer use a `.tsbuildinfo` that can outlive `dist/` and skip emitting files. A new `check:exports` step (also `prepack`) fails the release if any `exports`/`main`/`types` path is missing.
