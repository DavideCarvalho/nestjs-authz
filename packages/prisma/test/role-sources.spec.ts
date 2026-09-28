import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import { makeFakeClient } from './fake-client.js';

describe('PrismaAuthzStore — per-source role assignments (roleSources: true)', () => {
  const make = () => {
    const client = makeFakeClient();
    return { client, store: new PrismaAuthzStore(client, { roleSources: true }) };
  };

  it('assignRole records the default "manual" source', async () => {
    const { store } = make();
    await store.assignRole(1, 'editor');
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
  });

  it('setUserRoles replaces only that source; a role from two sources is kept', async () => {
    const { store } = make();
    await store.givePermissionToRole('editor', 'posts.edit');
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
  });

  it('removeRole: with a source removes that one, without removes every source', async () => {
    const { store } = make();
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.removeRole(1, 'editor', { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toHaveLength(1);
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.removeRole(1, 'editor');
    expect(await store.getRoleAssignments(1)).toEqual([]);
  });

  it('uses $transaction when the client provides it', async () => {
    const { client, store } = make();
    const $transaction = vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => fn(client));
    client.$transaction = $transaction;
    await store.setUserRoles(1, ['editor'], { source: 'scim' });
    expect($transaction).toHaveBeenCalledOnce();
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'scim', tenantId: null },
    ]);
  });
});

describe('PrismaAuthzStore — legacy schema (roleSources off, the default)', () => {
  it('never sends a `source` field, so a schema without the column keeps working', async () => {
    const client = makeFakeClient();
    const store = new PrismaAuthzStore(client);
    await store.assignRole(1, 'editor');
    await store.setUserRoles(1, ['viewer']);
    const rows = (client.userRole as unknown as { rows: Array<Record<string, unknown>> }).rows;
    expect(rows.every((r) => !('source' in r))).toBe(true);
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'viewer', source: 'manual', tenantId: null },
    ]);
  });

  it('rejects a non-default source with a migration hint', async () => {
    const store = new PrismaAuthzStore(makeFakeClient());
    await expect(store.setUserRoles(1, ['x'], { source: 'sso' })).rejects.toThrow(/roleSources/);
    await expect(store.assignRole(1, 'x', { source: 'sso' })).rejects.toThrow(/source String/);
  });
});
