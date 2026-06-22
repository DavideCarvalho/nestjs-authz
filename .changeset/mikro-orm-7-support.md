---
"@dudousxd/nestjs-authz-mikro-orm": minor
---

Support MikroORM 7 (peer `@mikro-orm/core` / `@mikro-orm/nestjs` widened to `^6 || ^7`).

MikroORM 7 relocated the entity decorators (`@Entity/@Property/@PrimaryKey/@Index`) out of `@mikro-orm/core` into a separate `@mikro-orm/decorators` package, and removed `MikroORM.getSchemaGenerator()`. To run on both v6 and v7 from a single codebase with no extra peer:

- The four authz entities are now defined with `EntitySchema` (the one definition style that lives in `@mikro-orm/core` on both majors) instead of decorators. The entity classes (`RoleEntity` … `UserRoleEntity`) are unchanged as the store's reference; their schemas are also exported (`RoleEntitySchema` … `UserRoleEntitySchema`) for BYO-table-name re-declaration.
- `ensureAuthzSchema` / `authzSchemaSql` now detect a `MikroORM` instance via its `em` property (present on both v6 and v7) instead of the v7-removed `getSchemaGenerator()`, and read the schema generator off the EM-bound platform.

Verified end-to-end against `@mikro-orm/core@7` + `@mikro-orm/sqlite@7` (and the existing v6 suite still passes).
