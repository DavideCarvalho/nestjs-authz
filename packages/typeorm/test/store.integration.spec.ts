import 'reflect-metadata';
import { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import { DataSource } from 'typeorm';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { AUTHZ_ENTITIES } from '../src/entities.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';

async function freshDataSource(): Promise<DataSource> {
  const ds = new DataSource({
    type: 'sqlite',
    database: ':memory:',
    entities: [...AUTHZ_ENTITIES],
    synchronize: false, // tables don't exist until ensureSchema()
  });
  await ds.initialize();
  return ds;
}

describe('TypeOrmAuthzStore (integration, sqlite)', () => {
  let ds: DataSource;
  let store: TypeOrmAuthzStore;

  beforeEach(async () => {
    ds = await freshDataSource();
    store = new TypeOrmAuthzStore(ds);
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
    const customDs = await freshDataSource();
    const custom = new TypeOrmAuthzStore(customDs, {
      tableNames: {
        roles: 'rbac_roles',
        permissions: 'rbac_perms',
        rolePermission: 'rbac_role_perm',
        userRole: 'rbac_user_role',
      },
    });
    await custom.ensureSchema();
    const qr = customDs.createQueryRunner();
    expect(await qr.hasTable('rbac_roles')).toBe(true);
    expect(await qr.hasTable('rbac_user_role')).toBe(true);
    await qr.release();

    await custom.givePermissionToRole('editor', 'posts.publish');
    await custom.assignRole(5, 'editor');
    expect(await custom.userHasPermission(5, 'posts.publish')).toBe(true);
    await customDs.destroy();
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
