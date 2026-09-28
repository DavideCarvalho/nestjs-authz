import 'reflect-metadata';
import { MikroORM } from '@mikro-orm/better-sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AUTHZ_ENTITIES } from '../src/entities.js';
import { MikroOrmAuthzStore } from '../src/mikro-orm-authz.store.js';
import { authzSchemaSql } from '../src/schema.js';

describe('per-source role assignments (MikroORM, sqlite)', () => {
  let orm: MikroORM;
  let store: MikroOrmAuthzStore;

  beforeEach(async () => {
    orm = await MikroORM.init({
      dbName: ':memory:',
      entities: [...AUTHZ_ENTITIES],
      allowGlobalContext: true,
    });
    store = new MikroOrmAuthzStore(orm.em);
    await store.ensureSchema();
    await store.givePermissionToRole('editor', 'posts.edit');
  });

  afterEach(async () => {
    await orm.close(true);
  });

  it('assignRole records the default "manual" source', async () => {
    await store.assignRole(1, 'editor');
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
  });

  it('setUserRoles replaces only that source; a role from two sources is kept', async () => {
    await store.assignRole(1, 'editor');
    await store.setUserRoles(1, ['editor', 'viewer'], { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
      { role: 'editor', source: 'sso', tenantId: null },
      { role: 'viewer', source: 'sso', tenantId: null },
    ]);
    expect((await store.getRolesForUser(1)).sort()).toEqual(['editor', 'viewer']);

    await store.setUserRoles(1, ['viewer'], { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
      { role: 'viewer', source: 'sso', tenantId: null },
    ]);
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(true);

    await store.setUserRoles(1, [], { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
  });

  it('setUserRoles without a source replaces the manual assignments', async () => {
    await store.setUserRoles(1, ['editor'], { source: 'scim' });
    await store.setUserRoles(1, ['viewer']);
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'scim', tenantId: null },
      { role: 'viewer', source: 'manual', tenantId: null },
    ]);
  });

  it('removeRole: with a source removes that one, without removes every source', async () => {
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.removeRole(1, 'editor', { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.removeRole(1, 'editor');
    expect(await store.getRoleAssignments(1)).toEqual([]);
  });

  it('the schema is in sync with the source column (no pending diff)', async () => {
    expect(await authzSchemaSql(orm)).toBe('');
  });
});
