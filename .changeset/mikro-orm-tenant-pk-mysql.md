---
"@dudousxd/nestjs-authz-mikro-orm": patch
---

`tenantScoped: true` works on MySQL. The user-role primary key (5 columns) was over MySQL's 3072-byte limit in utf8mb4, so the table could not be created. With `tenantScoped`, `role_id` is now 64 characters, as in the TypeORM adapter (role ids are store-generated UUIDs). On an existing tenant-scoped table, `ensureSchema` / `authzSchemaSql` shrink `role_id` from 191 to 64 characters. Without `tenantScoped`, nothing changes.
