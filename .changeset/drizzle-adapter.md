---
'@dudousxd/nestjs-authz-drizzle': minor
---

New package: `@dudousxd/nestjs-authz-drizzle` — the Drizzle ORM (Postgres) sibling of the typeorm/mikro-orm/prisma adapters.

- `compileScope(constraint, tableOrColumns)` / `applyScope(gate, Entity, table)` compile `gate.scope()` into a Drizzle `SQL` WHERE (fields resolved against the table's columns or an explicit allowlist map; values always bound; `allow-all` → `undefined`, `deny-all` → `1 = 0`).
- `DrizzleAuthzStore` — the same store surface as the TypeORM adapter (idempotent role/permission upserts, tenant-scoped role assignments, direct user permissions, `getUserAuthz`), over the canonical `authz_*` tables, plus `withDb(tx)` for caller transactions.
- `createAuthzTables({ tableNames, schema })` returns the tables as `pgTable`s to spread into your drizzle-kit schema; `ensureSchema()` / `authzSchemaDdl()` for non-drizzle-kit setups.
- `AuthzRbacModule` registers the `PERMISSION_PROVIDER` (with wildcard `getPermissions`) and `ROLE_PROVIDER` seams, tenant-aware via nestjs-context.
