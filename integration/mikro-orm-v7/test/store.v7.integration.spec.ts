import 'reflect-metadata';
import { createRequire } from 'node:module';
import { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { MikroORM } from '@mikro-orm/sqlite';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
// Import the package SOURCE (not the built dist / workspace symlink): doing so resolves its
// bare `@mikro-orm/core` import to THIS package's pinned v7 (see package.json), which is the
// only way decorator-free EntitySchema metadata is registered with the v7 runtime. The
// built package ships v6 as a devDependency, so a symlinked import would silently load v6.
import { AuthzRbacModule } from '../../../packages/mikro-orm/src/authz-rbac.module.js';
import { AUTHZ_ENTITIES, RoleEntity } from '../../../packages/mikro-orm/src/entities.js';
import { MikroOrmAuthzStore } from '../../../packages/mikro-orm/src/mikro-orm-authz.store.js';
import { AuthzRoleRepository } from '../../../packages/mikro-orm/src/repositories.js';
import { authzSchemaSql, ensureAuthzSchema } from '../../../packages/mikro-orm/src/schema.js';

const coreVersion: string = createRequire(import.meta.url)('@mikro-orm/core/package.json').version;

async function freshOrm(): Promise<MikroORM> {
  return MikroORM.init({
    dbName: ':memory:',
    entities: [...AUTHZ_ENTITIES],
    allowGlobalContext: true,
  });
}

describe(`MikroOrmAuthzStore on MikroORM ${coreVersion} (integration, sqlite)`, () => {
  let orm: MikroORM;
  let store: MikroOrmAuthzStore;

  beforeEach(async () => {
    orm = await freshOrm();
    store = new MikroOrmAuthzStore(orm.em);
    await store.ensureSchema();
  });

  afterEach(async () => {
    await orm.close(true);
  });

  it('runs against a MikroORM 7 core', () => {
    // Guard: if this ever resolves to v6 the whole suite is meaningless.
    expect(coreVersion.startsWith('7.')).toBe(true);
  });

  it('em.getRepository(RoleEntity) resolves the bound AuthzRoleRepository on v7', () => {
    // `EntityRepository` and the `repository:` EntitySchema option both live in
    // `@mikro-orm/core` on v6 and v7 — this is the v7 half of that proof.
    expect(orm.em.getRepository(RoleEntity)).toBeInstanceOf(AuthzRoleRepository);
  });

  it('ensureAuthzSchema creates all four authz tables non-destructively, idempotently', async () => {
    expect(await authzSchemaSql(orm)).toBe(''); // already current from beforeEach
    await ensureAuthzSchema(orm); // idempotent

    const connection = orm.em.getConnection();
    for (const tableName of [
      'authz_roles',
      'authz_permissions',
      'authz_role_permission',
      'authz_user_role',
    ]) {
      const rows = await connection.execute(
        `SELECT name FROM sqlite_master WHERE type='table' AND name = '${tableName}'`,
      );
      expect(rows).toHaveLength(1);
    }
  });

  it('createRole / assignRole / getRolesForUser round-trips', async () => {
    const roleId = await store.createRole('ADMIN');
    expect(typeof roleId).toBe('string');
    expect(await store.createRole('ADMIN')).toBe(roleId); // idempotent

    await store.assignRole({ type: 'User', id: 'u1' }, 'ADMIN');
    expect(await store.getRolesForUser({ type: 'User', id: 'u1' })).toEqual(['ADMIN']);
  });

  it('givePermissionToRole flows through to getPermissionsForUser', async () => {
    await store.givePermissionToRole('ADMIN', 'posts.publish');
    await store.givePermissionToRole('ADMIN', 'posts.delete');
    await store.assignRole({ type: 'User', id: 'u1' }, 'ADMIN');

    expect((await store.getPermissionsForUser({ type: 'User', id: 'u1' })).sort()).toEqual([
      'posts.delete',
      'posts.publish',
    ]);
    expect(await store.userHasPermission({ type: 'User', id: 'u1' }, 'posts.publish')).toBe(true);
    expect(await store.userHasPermission({ type: 'User', id: 'u1' }, 'posts.edit')).toBe(false);
    expect(await store.getPermissionsForUser({ type: 'User', id: 'u2' })).toEqual([]);
  });

  it('removeRole / revokePermissionFromRole are effective and non-fatal', async () => {
    await store.givePermissionToRole('ADMIN', 'posts.publish');
    await store.assignRole({ type: 'User', id: 'u1' }, 'ADMIN');
    expect(await store.userHasPermission({ type: 'User', id: 'u1' }, 'posts.publish')).toBe(true);

    await store.removeRole({ type: 'User', id: 'u1' }, 'ADMIN');
    expect(await store.getRolesForUser({ type: 'User', id: 'u1' })).toEqual([]);
    expect(await store.userHasPermission({ type: 'User', id: 'u1' }, 'posts.publish')).toBe(false);

    await store.removeRole({ type: 'User', id: 'u1' }, 'ghost'); // no-op
    await store.revokePermissionFromRole('ghost', 'nope'); // no-op
  });

  it('getUserAuthz aggregates roles + effective permissions', async () => {
    await store.givePermissionToRole('ADMIN', 'posts.publish');
    await store.givePermissionToRole('MODERATOR', 'comments.delete');
    await store.assignRole({ type: 'User', id: 'u1' }, 'ADMIN');
    await store.assignRole({ type: 'User', id: 'u1' }, 'MODERATOR');

    const authz = await store.getUserAuthz({ type: 'User', id: 'u1' });
    expect(authz.roles.sort()).toEqual(['ADMIN', 'MODERATOR']);
    expect(authz.permissions.sort()).toEqual(['comments.delete', 'posts.publish']);
  });

  it('Gate consults persisted RBAC via the permission + role seams on v7', async () => {
    await store.givePermissionToRole('ADMIN', 'posts.publish');
    await store.assignRole({ type: 'User', id: 'u1' }, 'ADMIN');

    const moduleRef = await Test.createTestingModule({
      imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
      providers: [PolicyRegistry, Gate],
    }).compile();
    await moduleRef.init();

    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ type: 'User', id: 'u1' }).allows('posts.publish')).toBe(true);
    expect(await gate.forUser({ type: 'User', id: 'u1' }).hasRole('ADMIN')).toBe(true);
    expect(await gate.forUser({ type: 'User', id: 'u2' }).hasRole('ADMIN')).toBe(false);

    await moduleRef.close();
  });
});
