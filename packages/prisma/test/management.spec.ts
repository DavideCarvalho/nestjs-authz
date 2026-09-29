import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import type { PrismaAuthzClientLike } from '../src/prisma-client.js';
import { makeFakeClient } from './fake-client.js';

const row = (userId: string, role: string, source = 'manual', userType = 'user') => ({
  userType,
  userId,
  role,
  source,
  tenantId: null,
});

const rows = (client: PrismaAuthzClientLike, model: keyof PrismaAuthzClientLike) =>
  (client[model] as unknown as { rows: Array<Record<string, unknown>> }).rows;

describe('PrismaAuthzStore — admin management operations (roleSources: true)', () => {
  const make = () => {
    const client = makeFakeClient();
    return { client, store: new PrismaAuthzStore(client, { roleSources: true }) };
  };

  it('deleteRole removes the role, its permission links and every assignment of it', async () => {
    const { client, store } = make();
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
    expect(rows(client, 'rolePermission')).toHaveLength(1);
    expect(rows(client, 'permission')).toHaveLength(2);
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(false);
  });

  it('syncRolePermissions replaces the set, creating the role/permissions when missing', async () => {
    const { store } = make();
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
    const { store } = make();
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.createRole('empty');
    expect(await store.getRolePermissions(['editor', 'empty', 'ghost'])).toEqual({
      editor: ['posts.edit'],
      empty: [],
    });
    expect(await store.getRolePermissions([])).toEqual({});
    expect(await store.getRolePermissions(['ghost'])).toEqual({});
  });

  it('listRoleAssignments filters by role, user and source; every row is global', async () => {
    const { store } = make();
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
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toEqual([]);
    expect(await store.listRoleAssignments({ role: 'viewer' })).toEqual([
      row('9', 'viewer', 'manual', 'bot'),
      row('2', 'viewer'),
    ]);
    expect(await store.listRoleAssignments({ role: ['admin', 'ghost'] })).toEqual([
      row('1', 'admin'),
    ]);
    expect(await store.listRoleAssignments({ role: [] })).toEqual([]);
    expect(await store.listRoleAssignments({ user: 1, source: 'sso' })).toEqual([
      row('1', 'editor', 'sso'),
    ]);
    expect(await store.listRoleAssignments({ user: { type: 'bot', id: '9' } })).toEqual([
      row('9', 'viewer', 'manual', 'bot'),
    ]);
  });

  it('removeUser deletes every assignment of that user only', async () => {
    const { store } = make();
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.assignRole(2, 'editor');
    await store.removeUser(1);
    expect(await store.listRoleAssignments({ user: 1 })).toEqual([]);
    expect(await store.getPermissionsForUser(2)).toEqual(['posts.edit']);
  });

  it('deleteRole and syncRolePermissions use $transaction when the client provides it', async () => {
    const { client, store } = make();
    const $transaction = vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(client));
    client.$transaction = $transaction;
    await store.syncRolePermissions('editor', ['posts.edit']);
    expect(await store.deleteRole('editor')).toBe(true);
    expect($transaction).toHaveBeenCalledTimes(2);
  });
});

describe('PrismaAuthzStore — admin management operations (legacy schema, roleSources off)', () => {
  it('listRoleAssignments: every row is manual; another source matches nothing', async () => {
    const client = makeFakeClient();
    const store = new PrismaAuthzStore(client);
    await store.assignRole(1, 'editor');
    expect(await store.listRoleAssignments({ source: 'manual' })).toEqual([row('1', 'editor')]);
    expect(await store.listRoleAssignments({ source: 'sso' })).toEqual([]);
    expect(rows(client, 'userRole').every((r) => !('source' in r))).toBe(true);
    await store.removeUser(1);
    expect(await store.listRoleAssignments()).toEqual([]);
  });
});
