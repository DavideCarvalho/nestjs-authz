import 'reflect-metadata';
import { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import type { DataSource } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
  targetDialect,
} from './support/datasource.js';

describeIntegration(`TypeOrmAuthzStore (integration, ${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let ds: DataSource;
  let store: TypeOrmAuthzStore;

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    ds = fx.ds;
    store = new TypeOrmAuthzStore(ds, fx.options);
    await store.ensureSchema();
  });

  afterEach(async () => {
    await ds.destroy();
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

  it('honors BYO table names', async () => {
    // A second fixture, but with explicit custom names (still unique-prefixed so the
    // shared container stays isolated) — proves the store qualifies every reference by
    // the configured name rather than a hard-coded default.
    const custom = await freshAuthzDataSource();
    const names = {
      roles: `${custom.names.roles}_rbac`,
      permissions: `${custom.names.permissions}_rbac`,
      rolePermission: `${custom.names.rolePermission}_rbac`,
      userRole: `${custom.names.userRole}_rbac`,
    };
    const customStore = new TypeOrmAuthzStore(custom.ds, { tableNames: names });
    await customStore.ensureSchema();
    const qr = custom.ds.createQueryRunner();
    expect(await qr.hasTable(names.roles)).toBe(true);
    expect(await qr.hasTable(names.userRole)).toBe(true);
    await qr.release();

    await customStore.givePermissionToRole('editor', 'posts.publish');
    await customStore.assignRole(5, 'editor');
    expect(await customStore.userHasPermission(5, 'posts.publish')).toBe(true);
    await custom.ds.destroy();
  });

  it('Gate.allows consults persisted permissions via the RBAC seam', async () => {
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole({ type: 'user', id: 42 }, 'editor');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    // A user holding the permission is granted the named, model-less ability.
    expect(await gate.forUser({ type: 'user', id: 42 }).allows('posts.publish')).toBe(true);
    // A user without it falls through → unresolved (no policy/gate defines it).
    await expect(gate.forUser({ type: 'user', id: 99 }).allows('posts.publish')).rejects.toThrow();

    await moduleRef.close();
  });

  it('Gate.allows honors persisted WILDCARD grants (posts.* → posts.update)', async () => {
    // Persist a wildcard permission; the core matcher should expand it.
    await store.givePermissionToRole('editor', 'posts.*');
    await store.assignRole({ type: 'user', id: 42 }, 'editor');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    const editor = gate.forUser({ type: 'user', id: 42 });
    // `posts.*` satisfies any posts.* ability.
    expect(await editor.allows('posts.update')).toBe(true);
    expect(await editor.allows('posts.publish')).toBe(true);
    // But not a different namespace → falls through to unresolved.
    await expect(editor.allows('comments.update')).rejects.toThrow();

    await moduleRef.close();
  });

  it('Gate.hasRole consults persisted roles via the ROLE_PROVIDER seam', async () => {
    await store.assignRole({ type: 'user', id: 42 }, 'editor');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    // The role assigned in the store is resolved for coarse `@Roles`/`hasRole` checks.
    expect(await gate.forUser({ type: 'user', id: 42 }).hasRole('editor')).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 42 }).hasAnyRole(['admin', 'editor'])).toBe(true);
    // A user without the role is denied.
    expect(await gate.forUser({ type: 'user', id: 99 }).hasRole('editor')).toBe(false);

    await moduleRef.close();
  });
});
