import 'reflect-metadata';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { DrizzleAuthzStore } from '../src/drizzle-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDb,
  targetDialect,
} from './support/db.js';

describeIntegration(`admin management operations (${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let store: DrizzleAuthzStore;

  beforeEach(async () => {
    fx = await freshAuthzDb();
    store = new DrizzleAuthzStore(fx.db, fx.options);
    await store.ensureSchema();
  });

  afterEach(async () => {
    await fx.close();
  });

  const count = async (table: string) =>
    Number((await fx.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${table}"`))[0]?.n);

  it('deleteRole removes the role, its permission links and every assignment of it', async () => {
    await store.syncRolePermissions('editor', ['posts.edit', 'posts.view']);
    await store.givePermissionToRole('viewer', 'posts.view');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.assignRole(2, 'editor', { tenantId: 'acme' });
    await store.assignRole(2, 'viewer', { tenantId: 'acme' });

    expect(await store.deleteRole('editor')).toBe(true);
    expect(await store.deleteRole('editor')).toBe(false);
    expect(await store.deleteRole('nope')).toBe(false);

    expect(await store.listRoleAssignments()).toEqual([
      { userType: 'user', userId: '2', role: 'viewer', source: 'manual', tenantId: 'acme' },
    ]);
    expect(await store.getRolePermissions(['editor', 'viewer'])).toEqual({
      viewer: ['posts.view'],
    });
    expect(await count(fx.names.rolePermission)).toBe(1);
    // Permissions are kept.
    expect(await count(fx.names.permissions)).toBe(2);
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(false);
  });

  it('syncRolePermissions replaces the set, creating the role/permissions when missing', async () => {
    await store.syncRolePermissions('editor', ['posts.edit', 'posts.view', 'posts.edit']);
    expect(await store.getRolePermissions(['editor'])).toEqual({
      editor: ['posts.edit', 'posts.view'],
    });
    await store.syncRolePermissions('editor', ['posts.view', 'posts.delete']);
    expect(await store.getRolePermissions(['editor'])).toEqual({
      editor: ['posts.delete', 'posts.view'],
    });
    await store.syncRolePermissions('editor', []);
    expect(await store.getRolePermissions(['editor'])).toEqual({ editor: [] });
  });

  it('syncRolePermissions only touches the named role', async () => {
    await store.givePermissionToRole('viewer', 'posts.view');
    await store.syncRolePermissions('editor', ['posts.view']);
    await store.syncRolePermissions('editor', []);
    expect(await store.getRolePermissions(['viewer', 'editor'])).toEqual({
      viewer: ['posts.view'],
      editor: [],
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

  it('listRoleAssignments filters by tenant (undefined / null / string), role, user and source', async () => {
    await store.assignRole(2, 'viewer');
    await store.assignRole(1, 'editor', { tenantId: 'acme' });
    await store.assignRole(1, 'admin');
    await store.assignRole(1, 'editor', { tenantId: 'acme', source: 'sso' });
    await store.assignRole({ type: 'bot', id: 9 }, 'viewer', { tenantId: 'other' });

    const g = (userId: string, role: string, source = 'manual', userType = 'user') => ({
      userType,
      userId,
      role,
      source,
      tenantId: null,
    });
    const t = (
      tenantId: string,
      userId: string,
      role: string,
      source = 'manual',
      userType = 'user',
    ) => ({
      userType,
      userId,
      role,
      source,
      tenantId,
    });

    expect(await store.listRoleAssignments()).toEqual([
      t('other', '9', 'viewer', 'manual', 'bot'),
      g('1', 'admin'),
      t('acme', '1', 'editor'),
      t('acme', '1', 'editor', 'sso'),
      g('2', 'viewer'),
    ]);
    expect(await store.listRoleAssignments({ tenantId: null })).toEqual([
      g('1', 'admin'),
      g('2', 'viewer'),
    ]);
    // A tenant id means ONLY that tenant's scoped rows — globals are not included.
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toEqual([
      t('acme', '1', 'editor'),
      t('acme', '1', 'editor', 'sso'),
    ]);
    expect(await store.listRoleAssignments({ tenantId: 'nobody' })).toEqual([]);
    expect(await store.listRoleAssignments({ role: 'viewer' })).toEqual([
      t('other', '9', 'viewer', 'manual', 'bot'),
      g('2', 'viewer'),
    ]);
    expect(await store.listRoleAssignments({ role: ['admin', 'viewer'], tenantId: null })).toEqual([
      g('1', 'admin'),
      g('2', 'viewer'),
    ]);
    expect(await store.listRoleAssignments({ role: [] })).toEqual([]);
    expect(await store.listRoleAssignments({ user: 1, source: 'sso' })).toEqual([
      t('acme', '1', 'editor', 'sso'),
    ]);
    expect(await store.listRoleAssignments({ user: { type: 'bot', id: '9' } })).toEqual([
      t('other', '9', 'viewer', 'manual', 'bot'),
    ]);
  });

  it('removeUser deletes every assignment and direct permission of that user only', async () => {
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { tenantId: 'acme', source: 'sso' });
    await store.giveUserPermission(1, 'billing.view');
    await store.assignRole(2, 'editor');
    await store.giveUserPermission(2, 'billing.view');

    await store.removeUser(1);

    expect(await store.listRoleAssignments({ user: 1 })).toEqual([]);
    expect(await store.getPermissionsForUser(1, { tenantId: 'acme' })).toEqual([]);
    expect((await store.getPermissionsForUser(2)).sort()).toEqual(['billing.view', 'posts.edit']);
    expect(await store.getRolePermissions(['editor'])).toEqual({ editor: ['posts.edit'] });
  });

  it('works inside the caller transaction (withDb(tx)) and rolls back with it', async () => {
    await store.givePermissionToRole('editor', 'posts.edit');
    await fx.db.transaction(async (tx) => {
      const txStore = store.withDb(tx);
      await txStore.createRole('viewer');
      await txStore.assignRole(1, 'viewer');
      await txStore.setUserRoles(1, ['editor'], { source: 'sso' });
      await txStore.syncRolePermissions('viewer', ['posts.view']);
      await txStore.deleteRole('viewer');
      await txStore.removeUser(2);
    });
    expect(await store.listRoleAssignments({ user: 1 })).toEqual([
      { userType: 'user', userId: '1', role: 'editor', source: 'sso', tenantId: null },
    ]);

    await expect(
      fx.db.transaction(async (tx) => {
        const txStore = store.withDb(tx);
        await txStore.syncRolePermissions('editor', ['posts.delete']);
        await txStore.deleteRole('ghost');
        await txStore.removeUser(1);
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(await store.getRolePermissions(['editor'])).toEqual({ editor: ['posts.edit'] });
    expect(await store.listRoleAssignments({ user: 1 })).toHaveLength(1);
  });
});
