---
"@dudousxd/nestjs-authz": minor
"@dudousxd/nestjs-authz-client": minor
"@dudousxd/nestjs-authz-react": minor
"@dudousxd/nestjs-authz-codegen": major
"@dudousxd/nestjs-authz-drizzle": major
"@dudousxd/nestjs-authz-inertia": major
"@dudousxd/nestjs-authz-mikro-orm": major
"@dudousxd/nestjs-authz-prisma": major
"@dudousxd/nestjs-authz-testing": major
"@dudousxd/nestjs-authz-typeorm": major
---

**Breaking:** require Node.js 24 or newer (`engines.node` is now `>=24`; it was `>=22`, and `>=20` for `-client` and `-react`). CI tests on Node 24 and 26. No API changes: see the Upgrading page in the docs.
