import 'reflect-metadata';
import { MikroORM } from '@mikro-orm/better-sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AUTHZ_ENTITIES } from '../src/entities.js';
import { MikroOrmAuthzStore } from '../src/mikro-orm-authz.store.js';

const row = (userId: string, role: string, source = 'manual', userType = 'user') => ({
  userType,
  userId,
  role,
  source,
  tenantId: null,
});

describe('admin management operations (MikroORM, sqlite)', () => {
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
  });

  afterEach(async () => {
    await orm.close(true);
  });

  const count = async (table: string) =>
    Number(
      (
        (await orm.em.getConnection().execute(`select count(*) as n from ${table}`)) as Array<{
          n: number;
        }>
      )[0]?.n,
    );

  it('deleteRole removes the role, its permission links and every assignment of it', async () => {
    await store.syncRolePermissions('editor', ['posts.edit', 'posts.view']);
    await store.givePermissionToRole('viewer', 'posts.view');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.assignRole(2, 'viewer');

    expect(await store.deleteRole('editor')).toBe(true);
    expect(await store.deleteRole('editor')).toBe(false);
    expect(await store.deleteRole('nope')).toBe(false);

    expect(await store.listRoleAssignments()).toEqual([row('2', 'viewer')]);
    expect(await store.getRolePermissions(['editor', 'viewer'])).toEqual({
      viewer: ['posts.view'],
    });
    expect(await count('authz_role_permission')).toBe(1);
    expect(await count('authz_permissions')).toBe(2);
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(false);
  });

  it('syncRolePermissions replaces the set, creating the role/permissions when missing', async () => {
    await store.givePermissionToRole('viewer', 'posts.view');
    await store.syncRolePermissions('editor', ['posts.edit', 'posts.view', 'posts.edit']);
    expect(await store.getRolePermissions(['editor'])).toEqual({
      editor: ['posts.edit', 'posts.view'],
    });
    await store.syncRolePermissions('editor', ['posts.view', 'posts.delete']);
    expect(await store.getRolePermissions(['editor'])).toEqual({
      editor: ['posts.delete', 'posts.view'],
    });
    await store.syncRolePermissions('editor', []);
    expect(await store.getRolePermissions(['editor', 'viewer'])).toEqual({
      editor: [],
      viewer: ['posts.view'],
    });
  });

  it('getRolePermissions: existing roles (even empty) are keys, missing roles are absent', async () => {
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.createRole('empty');
    expect(await store.getRolePermissions(['editor', 'empty', 'ghost'])).toEqual({
      editor: ['posts.edit'],
      empty: [],
    });
    expect(await store.getRolePermissions([])).toEqual({});
  });

  it('listRoleAssignments filters by role, user and source; every row is global', async () => {
    await store.assignRole(2, 'viewer');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'admin');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.assignRole({ type: 'bot', id: 9 }, 'viewer');

    const all = [
      row('9', 'viewer', 'manual', 'bot'),
      row('1', 'admin'),
      row('1', 'editor'),
      row('1', 'editor', 'sso'),
      row('2', 'viewer'),
    ];
    expect(await store.listRoleAssignments()).toEqual(all);
    expect(await store.listRoleAssignments({ tenantId: null })).toEqual(all);
    // No tenant-scoped assignments in this adapter: a tenant id matches nothing.
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toEqual([]);
    expect(await store.listRoleAssignments({ role: 'viewer' })).toEqual([
      row('9', 'viewer', 'manual', 'bot'),
      row('2', 'viewer'),
    ]);
    expect(await store.listRoleAssignments({ role: ['admin', 'ghost'] })).toEqual([
      row('1', 'admin'),
    ]);
    expect(await store.listRoleAssignments({ role: [] })).toEqual([]);
    expect(await store.listRoleAssignments({ role: 'ghost' })).toEqual([]);
    expect(await store.listRoleAssignments({ user: 1, source: 'sso' })).toEqual([
      row('1', 'editor', 'sso'),
    ]);
    expect(await store.listRoleAssignments({ user: { type: 'bot', id: '9' } })).toEqual([
      row('9', 'viewer', 'manual', 'bot'),
    ]);
  });

  it('removeUser deletes every assignment of that user only', async () => {
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.assignRole(2, 'editor');

    await store.removeUser(1);

    expect(await store.listRoleAssignments({ user: 1 })).toEqual([]);
    expect(await store.getPermissionsForUser(1)).toEqual([]);
    expect(await store.getPermissionsForUser(2)).toEqual(['posts.edit']);
    expect(await store.getRolePermissions(['editor'])).toEqual({ editor: ['posts.edit'] });
  });
});
