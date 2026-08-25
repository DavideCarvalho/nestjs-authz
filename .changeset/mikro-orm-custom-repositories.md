---
"@dudousxd/nestjs-authz-mikro-orm": minor
---

Ship typed MikroORM repositories for the four authz entities, and a schema factory for custom table names.

- New `AuthzRoleRepository`, `AuthzPermissionRepository`, `AuthzRolePermissionRepository` and `AuthzUserRoleRepository` (empty `EntityRepository` subclasses), bound to the entities via `repository: () => ...` on each `EntitySchema` plus an `[EntityRepositoryType]` marker on each entity class. `em.getRepository(RoleEntity)` now returns — and is typed as — `AuthzRoleRepository`, and `MikroOrmModule.forFeature([...AUTHZ_ENTITY_CLASSES])` registers each repository class as its own DI token, so host apps inject by type instead of threading the entity class through every `em.find(RoleEntity, ...)`.
- New `createAuthzEntitySchemas(tableNames?)` — the supported way to relocate the authz tables. It carries the repository binding and derives the index names from the given table names; hand-writing a replacement `EntitySchema` (the previously documented path) silently dropped both. `AUTHZ_ENTITIES` and `RoleEntitySchema` … `UserRoleEntitySchema` are now produced by this factory with the default names, so they are unchanged.
- New `AUTHZ_ENTITY_CLASSES` export (the four classes in dependency order) for `MikroOrmModule.forFeature()`, which matches on `meta.class`.
- `ensureAuthzSchema` / `authzSchemaSql` now read the four physical table names off the live metadata instead of hard-coding the `authz_*` literals, so relocated tables are created too.

`EntityRepository`, `EntityRepositoryType` and the `repository` option on `EntitySchemaMetadata` all live in `@mikro-orm/core` on both MikroORM 6 and 7, so this adds no peer and no decorator import. Verified against the v6 suite and the pinned `@mikro-orm/core@7` integration suite.

`MikroOrmAuthzStore` is unchanged.
