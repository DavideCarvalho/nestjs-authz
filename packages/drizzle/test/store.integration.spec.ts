import 'reflect-metadata';
import { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { DrizzleAuthzStore } from '../src/drizzle-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDb,
  targetDialect,
} from './support/db.js';

async function tableExists(fx: AuthzFixture, name: string, schema = 'public'): Promise<boolean> {
  const rows = await fx.query(
    'SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2',
    [schema, name],
  );
  return rows.length > 0;
}

describeIntegration(`DrizzleAuthzStore (integration, ${targetDialect()})`, () => {
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
    const names = {
      roles: `${fx.names.roles}_rbac`,
      permissions: `${fx.names.permissions}_rbac`,
      rolePermission: `${fx.names.rolePermission}_rbac`,
      userRole: `${fx.names.userRole}_rbac`,
      userPermission: `${fx.names.userPermission}_rbac`,
    };
    const customStore = new DrizzleAuthzStore(fx.db, { tableNames: names });
    await customStore.ensureSchema();
    expect(await tableExists(fx, names.roles)).toBe(true);
    expect(await tableExists(fx, names.userRole)).toBe(true);

    await customStore.givePermissionToRole('editor', 'posts.publish');
    await customStore.assignRole(5, 'editor');
    expect(await customStore.userHasPermission(5, 'posts.publish')).toBe(true);
    // The default-named fixture tables are untouched.
    expect(await store.userHasPermission(5, 'posts.publish')).toBe(false);
  });

  it('honors a Postgres schema', async () => {
    const schema = `${fx.names.roles}_s`;
    const scoped = new DrizzleAuthzStore(fx.db, { schema });
    await scoped.ensureSchema();
    await scoped.ensureSchema(); // idempotent
    expect(await tableExists(fx, 'authz_roles', schema)).toBe(true);
    expect(await tableExists(fx, 'authz_user_permission', schema)).toBe(true);

    await scoped.givePermissionToRole('editor', 'posts.publish');
    await scoped.assignRole(5, 'editor');
    expect(await scoped.getUserAuthz(5)).toEqual({
      roles: ['editor'],
      permissions: ['posts.publish'],
    });
    await fx.query(`DROP SCHEMA "${schema}" CASCADE`);
  });

  it('runs inside a caller transaction (withDb) and rolls back with it', async () => {
    await expect(
      fx.db.transaction(async (tx) => {
        await store.withDb(tx).assignRole(3, 'editor');
        expect(await store.withDb(tx).getRolesForUser(3)).toEqual(['editor']);
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(await store.getRolesForUser(3)).toEqual([]);
  });

  it('concurrent createRole calls converge on one row', async () => {
    const ids = await Promise.all([1, 2, 3, 4].map(() => store.createRole('racer')));
    expect(new Set(ids).size).toBe(1);
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
