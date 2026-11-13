import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { AuthzModule, Gate } from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { DataSource, type DataSourceOptions } from 'typeorm';
import { afterEach, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { authzEntities } from '../src/entities.js';
import { ensureAuthzSchema } from '../src/schema.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
} from './support/datasource.js';

/**
 * The `schema` option: the authz tables live in their own Postgres schema (MySQL database), and
 * nothing lands in the connection's default one. On SQLite it fails.
 */
describeIntegration('schema option', () => {
  let fx: AuthzFixture;
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    for (const cleanup of cleanups.splice(0)) await cleanup().catch(() => {});
    if (fx?.ds.isInitialized) await fx.ds.destroy();
  });

  /** Tables of a schema (Postgres) / database (MySQL) whose name starts with `prefix`. */
  async function tablesIn(ds: DataSource, schema: string, prefix: string): Promise<string[]> {
    const mysql = ds.options.type === 'mysql';
    const rows = (await ds.query(
      `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = ${mysql ? '?' : '$1'}`,
      [schema],
    )) as Array<{ name?: string; NAME?: string; TABLE_NAME?: string }>;
    return rows
      .map((r) => r.name ?? r.NAME ?? r.TABLE_NAME ?? '')
      .filter((n) => n.startsWith(prefix))
      .sort();
  }

  /** A fresh schema name, dropped after the test. */
  function freshSchema(ds: DataSource): string {
    const schema = `authz_${randomUUID().replace(/-/g, '').slice(0, 10)}`;
    cleanups.push(async () => {
      await ds.query(
        ds.options.type === 'mysql'
          ? `DROP DATABASE IF EXISTS \`${schema}\``
          : `DROP SCHEMA IF EXISTS "${schema}" CASCADE`,
      );
    });
    return schema;
  }

  it('fails on SQLite, at construction and in ensureAuthzSchema', async () => {
    fx = await freshAuthzDataSource();
    if (fx.dialect !== 'sqlite') return;
    expect(() => new TypeOrmAuthzStore(fx.ds, { ...fx.options, schema: 'authz' })).toThrow(
      /not supported on SQLite/,
    );
    await expect(ensureAuthzSchema(fx.ds, { schema: 'authz' })).rejects.toThrow(
      /not supported on SQLite/,
    );
  });

  it('validates the name', async () => {
    fx = await freshAuthzDataSource();
    expect(() => new TypeOrmAuthzStore(fx.ds, { schema: 'a.b' })).toThrow(/Unsafe/);
    expect(() => new TypeOrmAuthzStore(fx.ds, { schema: 'a'.repeat(64) })).toThrow(/63/);
  });

  it('creates the schema and every table in it; nothing in the default schema', async () => {
    fx = await freshAuthzDataSource();
    if (fx.dialect === 'sqlite') return;
    const schema = freshSchema(fx.ds);
    const prefix = fx.names.roles.replace(/_roles$/, '');
    const store = new TypeOrmAuthzStore(fx.ds, { ...fx.options, schema });
    await store.ensureSchema();
    await store.ensureSchema(); // a second boot is a no-op

    expect(await tablesIn(fx.ds, schema, prefix)).toEqual(
      [
        fx.names.permissions,
        fx.names.rolePermission,
        fx.names.roles,
        fx.names.userPermission,
        fx.names.userRole,
      ].sort(),
    );
    const home = fx.dialect === 'mysql' ? String(fx.ds.options.database) : 'public';
    expect(await tablesIn(fx.ds, home, prefix)).toEqual([]);

    const alice = { type: 'user', id: '1' };
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.giveUserPermission(alice, 'reports.view');
    expect(await store.getRolesForUser(alice, { tenantId: 'acme' })).toEqual(['editor']);
    expect((await store.getPermissionsForUser(alice, { tenantId: 'acme' })).sort()).toEqual([
      'posts.publish',
      'reports.view',
    ]);
    expect(await store.userHasPermission(alice, 'posts.publish', { tenantId: 'acme' })).toBe(true);
    expect(await store.listRoleAssignments({ role: 'editor' })).toHaveLength(1);
    expect(await store.deleteRole('editor')).toBe(true);
  });

  it('the RBAC module boots and checks in the schema', async () => {
    fx = await freshAuthzDataSource();
    if (fx.dialect === 'sqlite') return;
    const schema = freshSchema(fx.ds);
    const store = new TypeOrmAuthzStore(fx.ds, { ...fx.options, schema });
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({ store }),
      ],
    }).compile();
    await moduleRef.init();
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole({ id: '1' }, 'editor');
    expect(await moduleRef.get(Gate).forUser({ id: '1' }).allows('posts.publish')).toBe(true);
    await moduleRef.close();
  });

  it('authzEntities() puts synchronized tables in the schema', async () => {
    fx = await freshAuthzDataSource();
    if (fx.dialect === 'sqlite') return;
    const schema = freshSchema(fx.ds);
    const type = fx.dialect === 'mysql' ? 'mysql' : 'postgres';
    const prefix = fx.names.roles.replace(/_roles$/, '');
    // The schema must exist before TypeORM synchronizes into it.
    await new TypeOrmAuthzStore(fx.ds, { ...fx.options, schema }).ensureSchema();
    await fx.ds.query(
      type === 'mysql' ? `DROP DATABASE \`${schema}\`` : `DROP SCHEMA "${schema}" CASCADE`,
    );
    await fx.ds.query(
      type === 'mysql' ? `CREATE DATABASE \`${schema}\`` : `CREATE SCHEMA "${schema}"`,
    );
    const ds = new DataSource({
      ...(fx.ds.options as object),
      entities: authzEntities({ schema, type, tableNames: fx.names }),
      synchronize: true,
    } as DataSourceOptions);
    await ds.initialize();
    try {
      expect(await tablesIn(ds, schema, prefix)).toHaveLength(5);
      const store = new TypeOrmAuthzStore(ds, { ...fx.options, schema });
      await store.ensureSchema(); // finds the factory entities' metadata
      await store.assignRole({ id: '9' }, 'viewer');
      expect(await store.getRolesForUser({ id: '9' })).toEqual(['viewer']);
    } finally {
      await ds.destroy();
    }
  });
});
