import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { AuthzModule, Gate } from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { afterEach, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { DrizzleAuthzStore } from '../src/drizzle-authz.store.js';
import { createAuthzTables } from '../src/schema.js';
import { type AuthzFixture, describeIntegration, freshAuthzDb } from './support/db.js';

/** The `schema` option: every authz table and index in its own schema, nothing in `public`. */
describeIntegration('schema option (Postgres)', () => {
  let fx: AuthzFixture | undefined;
  let schema: string;

  afterEach(async () => {
    if (!fx) return;
    await fx.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`).catch(() => {});
    await fx.close();
    fx = undefined;
  });

  async function fresh() {
    const db = await freshAuthzDb();
    fx = db;
    schema = `authz_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
    return new DrizzleAuthzStore(db.db, { ...db.options, schema });
  }

  const relations = async (kind: 'tables' | 'indexes', where: string) =>
    (
      await fx!.query<{ name: string }>(
        kind === 'tables'
          ? 'SELECT table_name AS name FROM information_schema.tables WHERE table_schema = $1'
          : 'SELECT indexname AS name FROM pg_indexes WHERE schemaname = $1',
        [where],
      )
    )
      .map((r) => r.name)
      .filter((n) => n.startsWith(fx!.names.roles.replace(/_roles$/, '')))
      .sort();

  it('creates the schema, the tables and their indexes in it; nothing in public', async () => {
    const store = await fresh();
    await store.ensureSchema();
    await store.ensureSchema(); // a second boot is a no-op

    expect(await relations('tables', schema)).toEqual(
      [
        fx!.names.permissions,
        fx!.names.rolePermission,
        fx!.names.roles,
        fx!.names.userPermission,
        fx!.names.userRole,
      ].sort(),
    );
    expect(await relations('indexes', schema)).toContain(`${fx!.names.userRole}_user_idx`);
    expect(await relations('tables', 'public')).toEqual([]);
    expect(await relations('indexes', 'public')).toEqual([]);
  });

  it('reads and writes in the schema', async () => {
    const store = await fresh();
    await store.ensureSchema();
    const alice = { type: 'user', id: '1' };
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.giveUserPermission(alice, 'reports.view');
    expect(await store.getRolesForUser(alice, { tenantId: 'acme' })).toEqual(['editor']);
    expect((await store.getPermissionsForUser(alice, { tenantId: 'acme' })).sort()).toEqual([
      'posts.publish',
      'reports.view',
    ]);
    await store.setUserRoles(alice, ['viewer'], { source: 'sso' });
    expect((await store.listRoleAssignments({ user: alice })).map((a) => a.role).sort()).toEqual([
      'editor',
      'viewer',
    ]);
    expect(await store.deleteRole('editor')).toBe(true);
  });

  it('the RBAC module boots (creating the schema) and checks in it', async () => {
    fx = await freshAuthzDb();
    schema = `authz_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
    const store = new DrizzleAuthzStore(fx!.db, { ...fx!.options, schema });
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({ store, autoCreateSchema: true }),
      ],
    }).compile();
    await moduleRef.init();
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole({ id: '1' }, 'editor');
    expect(await moduleRef.get(Gate).forUser({ id: '1' }).allows('posts.publish')).toBe(true);
    await moduleRef.close();
  });

  it('validates the name', () => {
    expect(() => createAuthzTables({ schema: 'a'.repeat(64) })).toThrow(/63/);
  });
});
