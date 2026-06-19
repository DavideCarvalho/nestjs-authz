import 'reflect-metadata';
import { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import { makeFakeClient } from './fake-client.js';

describe('PrismaAuthzStore (structural fake client)', () => {
  let store: PrismaAuthzStore;
  let client: ReturnType<typeof makeFakeClient>;

  beforeEach(() => {
    client = makeFakeClient();
    store = new PrismaAuthzStore(client);
  });

  it('ensureSchema is a no-op (consumer-managed schema)', async () => {
    await expect(store.ensureSchema()).resolves.toBeUndefined();
  });

  it('assign role → user gains the role’s permissions', async () => {
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole({ type: 'user', id: 7 }, 'editor');

    expect(await store.getRolesForUser({ type: 'user', id: 7 })).toEqual(['editor']);
    expect(await store.getPermissionsForUser({ type: 'user', id: 7 })).toEqual(['posts.publish']);
    expect(await store.userHasPermission({ type: 'user', id: 7 }, 'posts.publish')).toBe(true);
    expect(await store.userHasPermission({ type: 'user', id: 7 }, 'posts.delete')).toBe(false);
    // A different user gains nothing.
    expect(await store.userHasPermission({ type: 'user', id: 8 }, 'posts.publish')).toBe(false);
  });

  it('removeRole / revokePermissionFromRole are non-fatal and effective', async () => {
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.assignRole(7, 'editor'); // bare-id form → { type: 'user', id: '7' }

    expect((await store.getPermissionsForUser(7)).sort()).toEqual(['posts.edit', 'posts.publish']);

    await store.revokePermissionFromRole('editor', 'posts.publish');
    expect(await store.userHasPermission(7, 'posts.publish')).toBe(false);
    expect(await store.userHasPermission(7, 'posts.edit')).toBe(true);

    await store.removeRole(7, 'editor');
    expect(await store.getRolesForUser(7)).toEqual([]);
    // no-ops on absent links
    await store.removeRole(7, 'ghost');
    await store.revokePermissionFromRole('ghost', 'nope');
  });

  it('idempotent assign + getUserAuthz aggregates roles + permissions', async () => {
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('moderator', 'comments.delete');
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor'); // idempotent
    await store.assignRole(1, 'moderator');

    const authz = await store.getUserAuthz(1);
    expect(authz.roles.sort()).toEqual(['editor', 'moderator']);
    expect(authz.permissions.sort()).toEqual(['comments.delete', 'posts.publish']);
  });

  it('createRole / createPermission are idempotent (no duplicate rows)', async () => {
    const r1 = await store.createRole('editor');
    const r2 = await store.createRole('editor');
    expect(r1).toBe(r2);
    const p1 = await store.createPermission('posts.publish');
    const p2 = await store.createPermission('posts.publish');
    expect(p1).toBe(p2);
  });

  it('Gate.allows consults persisted permissions via the RBAC seam', async () => {
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole({ type: 'user', id: 42 }, 'editor');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ store })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ type: 'user', id: 42 }).allows('posts.publish')).toBe(true);
    await expect(gate.forUser({ type: 'user', id: 99 }).allows('posts.publish')).rejects.toThrow();

    await moduleRef.close();
  });

  it('Gate.hasRole consults persisted roles via the ROLE_PROVIDER seam', async () => {
    await store.assignRole({ type: 'user', id: 42 }, 'editor');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ store })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ type: 'user', id: 42 }).hasRole('editor')).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 42 }).hasAnyRole(['admin', 'editor'])).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 99 }).hasRole('editor')).toBe(false);

    await moduleRef.close();
  });

  it('raw fast path: $queryRaw client returns full deduped set (wildcard + 2 roles)', async () => {
    // editor grants a concrete + a WILDCARD permission; admin re-grants posts.* (dedupe).
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.givePermissionToRole('editor', 'posts.*');
    await store.givePermissionToRole('admin', 'posts.*');
    await store.givePermissionToRole('admin', 'users.ban');
    await store.assignRole({ type: 'user', id: 7 }, 'editor');
    await store.assignRole({ type: 'user', id: 7 }, 'admin');

    // The default fake exposes $queryRaw, so the store takes the raw branch.
    expect(typeof client.$queryRaw).toBe('function');
    expect((await store.getPermissionsForUser({ type: 'user', id: 7 })).sort()).toEqual([
      'posts.*',
      'posts.edit',
      'users.ban',
    ]);
    // Wildcard grant is returned as a NAME (not expanded / existence-checked).
    expect(await store.userHasPermission({ type: 'user', id: 7 }, 'posts.*')).toBe(true);
  });

  it('fallback path: client WITHOUT $queryRaw returns the same set via 3 queries', async () => {
    const noRaw = makeFakeClient({ rawQuery: false });
    const s = new PrismaAuthzStore(noRaw);
    await s.givePermissionToRole('editor', 'posts.edit');
    await s.givePermissionToRole('editor', 'posts.*');
    await s.givePermissionToRole('admin', 'posts.*');
    await s.givePermissionToRole('admin', 'users.ban');
    await s.assignRole({ type: 'user', id: 7 }, 'editor');
    await s.assignRole({ type: 'user', id: 7 }, 'admin');

    expect(noRaw.$queryRaw).toBeUndefined();
    expect((await s.getPermissionsForUser({ type: 'user', id: 7 })).sort()).toEqual([
      'posts.*',
      'posts.edit',
      'users.ban',
    ]);
  });

  it('fallback path: $queryRaw that throws degrades to the 3-query path', async () => {
    const throwing = makeFakeClient({ rawQuery: 'throw' });
    const s = new PrismaAuthzStore(throwing);
    await s.givePermissionToRole('editor', 'posts.edit');
    await s.givePermissionToRole('admin', 'users.ban');
    await s.assignRole({ type: 'user', id: 7 }, 'editor');
    await s.assignRole({ type: 'user', id: 7 }, 'admin');

    expect((await s.getPermissionsForUser({ type: 'user', id: 7 })).sort()).toEqual([
      'posts.edit',
      'users.ban',
    ]);
  });

  it('module accepts a raw `client` (builds the store internally)', async () => {
    const c = makeFakeClient();
    const s = new PrismaAuthzStore(c);
    await s.givePermissionToRole('editor', 'posts.publish');
    await s.assignRole(5, 'editor');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ client: c })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ id: 5 }).allows('posts.publish')).toBe(true);

    await moduleRef.close();
  });
});
