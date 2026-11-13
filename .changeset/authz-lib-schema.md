---
"@dudousxd/nestjs-authz-typeorm": minor
"@dudousxd/nestjs-authz-drizzle": minor
"@dudousxd/nestjs-authz-mikro-orm": minor
"@dudousxd/nestjs-authz-prisma": minor
---

A `schema` option puts the authz tables in their own database schema: a Postgres schema, or a MySQL database. Every statement names it, and `search_path` is never used.

- **TypeORM** (Postgres and MySQL): `storeOptions.schema`. Adds `authzEntities({ schema, type, tableNames })` for synchronize/migration-generated setups.
- **Drizzle** (Postgres): `createAuthzTables({ schema })` / `storeOptions.schema`.
- **MikroORM** (Postgres and MySQL): `createAuthzEntitySchemas(names, { schema })`. The store reads the schema from the entity metadata and qualifies its raw SQL. On MySQL, the heal narrows MikroORM's diff against the target database's `information_schema`. `authzSchemaSql()` includes the create statement.
- **Prisma** (Postgres): the `schema` option, for models with `@@schema`. The fast path uses `$queryRawUnsafe` with the schema in the SQL and every value bound.

Shared behaviour:
- Auto-create makes the schema only when the catalog says it is missing. A failure names the grant needed.
- On SQLite, a `schema` fails at boot. Prisma refuses it on MySQL and SQLite.
- Names are validated (a safe identifier, at most 63 characters).
- Without `schema`, nothing changes.
