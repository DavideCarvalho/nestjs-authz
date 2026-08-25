import { EntityRepository } from '@mikro-orm/core';
import type {
  PermissionEntity,
  RoleEntity,
  RolePermissionEntity,
  UserRoleEntity,
} from './entities.js';

/**
 * Typed repositories for the four authz entities, so a host app injects `AuthzRoleRepository`
 * by type instead of threading the entity class through `em.find(RoleEntity, ...)` at every
 * call site.
 *
 * The binding is two-sided: `repository: () => ...` on each `EntitySchema` (what
 * `em.getRepository()` and `MikroOrmModule.forFeature()` read at runtime) plus the
 * `[EntityRepositoryType]` marker on each entity class (what makes the return type narrow).
 *
 * `EntityRepository` is exported from `@mikro-orm/core` on both MikroORM 6 and 7, so this
 * needs no extra peer and no decorator import.
 *
 * The bodies are intentionally empty — this package ships no query surface beyond
 * `MikroOrmAuthzStore`; they exist to give the four entities an injectable identity.
 */
export class AuthzRoleRepository extends EntityRepository<RoleEntity> {}

export class AuthzPermissionRepository extends EntityRepository<PermissionEntity> {}

export class AuthzRolePermissionRepository extends EntityRepository<RolePermissionEntity> {}

export class AuthzUserRoleRepository extends EntityRepository<UserRoleEntity> {}
