import 'reflect-metadata';
import { MikroORM } from '@mikro-orm/better-sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { RoleEntity, createAuthzEntitySchemas } from '../src/entities.js';
import { MikroOrmAuthzStore } from '../src/mikro-orm-authz.store.js';
import { AuthzRoleRepository } from '../src/repositories.js';
import { authzSchemaSql, ensureAuthzSchema } from '../src/schema.js';

const TABLE_NAMES = {
  roles: 'app_roles',
  permissions: 'app_permissions',
  rolePermission: 'app_role_permission',
  userRole: 'app_user_role',
};

// This file owns the whole process (vitest isolates per file): `createAuthzEntitySchemas`
// re-registers the four classes in EntitySchema's global REGISTRY, so the renamed schemas
// must not leak into the specs that assert the default table names.
describe('createAuthzEntitySchemas (integration, sqlite)', () => {
  let orm: MikroORM;

  beforeEach(async () => {
    orm = await MikroORM.init({
      dbName: ':memory:',
      entities: [...createAuthzEntitySchemas(TABLE_NAMES).all],
      allowGlobalContext: true,
    });
  });

  afterEach(async () => {
    await orm.close(true);
  });

  it('relocates the tables and still creates them through ensureAuthzSchema', async () => {
    expect(await authzSchemaSql(orm)).toMatch(/app_roles/i);
    await ensureAuthzSchema(orm);

    const conn = orm.em.getConnection();
    for (const t of Object.values(TABLE_NAMES)) {
      const rows = await conn.execute(
        `SELECT name FROM sqlite_master WHERE type='table' AND name = '${t}'`,
      );
      expect(rows).toHaveLength(1);
    }
    // Nothing was created under the default names.
    const defaults = await conn.execute(
      "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'authz_%'",
    );
    expect(defaults).toHaveLength(0);
  });

  it('carries the repository binding over to the renamed tables', async () => {
    await ensureAuthzSchema(orm);
    expect(orm.em.getRepository(RoleEntity)).toBeInstanceOf(AuthzRoleRepository);
  });

  it('the store round-trips against the renamed tables', async () => {
    const store = new MikroOrmAuthzStore(orm.em);
    await store.ensureSchema();
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole({ type: 'user', id: 7 }, 'editor');

    expect(await store.getRolesForUser({ type: 'user', id: 7 })).toEqual(['editor']);
    expect(await store.userHasPermission({ type: 'user', id: 7 }, 'posts.publish')).toBe(true);
  });
});
