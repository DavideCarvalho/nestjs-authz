import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { AuthzModule, Gate } from '@dudousxd/nestjs-authz';
import { MikroORM as SqliteOrm } from '@mikro-orm/better-sqlite';
import type { EntityManager, MikroORM } from '@mikro-orm/core';
import { MikroORM as MysqlOrm } from '@mikro-orm/mysql';
import { MikroORM as PgOrm } from '@mikro-orm/postgresql';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { createAuthzEntitySchemas } from '../src/entities.js';
import { MikroOrmAuthzStore } from '../src/mikro-orm-authz.store.js';
import { authzSchemaSql, ensureAuthzSchema } from '../src/schema.js';

/**
 * The `schema` option: the authz tables in their own Postgres schema (MySQL database), nothing
 * in the connection's own. `pnpm test:db:pg` / `test:db:mysql` run it on a container; the default
 * run covers SQLite, where it fails.
 */
const dialect = process.env.AUTHZ_TEST_DIALECT as 'postgres' | 'mysql' | undefined;
const describeDb = dialect && !process.env.AUTHZ_TEST_SKIP ? describe : describe.skip;

const uid = () => randomUUID().replace(/-/g, '').slice(0, 10);

function names() {
  const prefix = `t_${uid()}`;
  return {
    prefix,
    tables: {
      roles: `${prefix}_roles`,
      permissions: `${prefix}_permissions`,
      rolePermission: `${prefix}_role_permission`,
      userRole: `${prefix}_user_role`,
    },
  };
}

describe('schema option on SQLite', () => {
  it('the store and ensureAuthzSchema fail with a clear message', async () => {
    const { tables } = names();
    const orm = await SqliteOrm.init({
      dbName: ':memory:',
      entities: createAuthzEntitySchemas(tables, { schema: 'authz' }).all,
      allowGlobalContext: true,
    });
    try {
      const em = orm.em as unknown as EntityManager;
      expect(() => new MikroOrmAuthzStore(em)).toThrow(/not supported on SQLite/);
      await expect(ensureAuthzSchema(em)).rejects.toThrow(/not supported on SQLite/);
    } finally {
      await orm.close(true);
    }
  });

  it('validates the name', () => {
    expect(() => createAuthzEntitySchemas({}, { schema: 'a.b' })).toThrow(/Unsafe/);
    expect(() => createAuthzEntitySchemas({}, { schema: 'a'.repeat(64) })).toThrow(/63/);
  });
});

describeDb(`schema option (${dialect})`, () => {
  const opened: MikroORM[] = [];
  const schemas: string[] = [];
  let admin: MikroORM | undefined;

  afterEach(async () => {
    for (const orm of opened.splice(0)) await orm.close(true);
    for (const schema of schemas.splice(0)) {
      await admin?.em
        .getConnection()
        .execute(
          dialect === 'mysql'
            ? `drop database if exists \`${schema}\``
            : `drop schema if exists "${schema}" cascade`,
        );
    }
    await admin?.close(true);
    admin = undefined;
  });

  const home = () =>
    dialect === 'mysql' ? (process.env.AUTHZ_TEST_MYSQL_DB ?? 'authz_test') : 'public';

  async function open(entities: unknown[]): Promise<MikroORM> {
    const common = { entities: entities as never[], allowGlobalContext: true, debug: false };
    const orm =
      dialect === 'mysql'
        ? await MysqlOrm.init({
            ...common,
            host: process.env.AUTHZ_TEST_MYSQL_HOST,
            port: Number(process.env.AUTHZ_TEST_MYSQL_PORT ?? 3306),
            user: process.env.AUTHZ_TEST_MYSQL_USER ?? 'root',
            password: process.env.AUTHZ_TEST_MYSQL_PASSWORD ?? 'root',
            dbName: home(),
          })
        : await PgOrm.init({
            ...common,
            host: process.env.AUTHZ_TEST_PG_HOST,
            port: Number(process.env.AUTHZ_TEST_PG_PORT ?? 5432),
            user: process.env.AUTHZ_TEST_PG_USER ?? 'postgres',
            password: process.env.AUTHZ_TEST_PG_PASSWORD ?? 'postgres',
            dbName: process.env.AUTHZ_TEST_PG_DB ?? 'authz_test',
          });
    opened.push(orm as unknown as MikroORM);
    return orm as unknown as MikroORM;
  }

  async function tablesIn(orm: MikroORM, schema: string, prefix: string): Promise<string[]> {
    const rows = (await orm.em
      .getConnection()
      .execute('select table_name as name from information_schema.tables where table_schema = ?', [
        schema,
      ])) as Array<{ name?: string; NAME?: string; TABLE_NAME?: string }>;
    return rows
      .map((r) => r.name ?? r.NAME ?? r.TABLE_NAME ?? '')
      .filter((n) => n.startsWith(prefix))
      .sort();
  }

  async function fresh() {
    const { prefix, tables } = names();
    const schema = `authz_${uid()}`;
    schemas.push(schema);
    admin ??= await open(createAuthzEntitySchemas(names().tables).all).then((orm) => {
      opened.pop();
      return orm;
    });
    // Tenant-scoped on both dialects: the 5-column user-role key fits MySQL's 3072-byte limit.
    const authz = createAuthzEntitySchemas(tables, { schema, tenantScoped: true });
    const orm = await open(authz.all);
    return { orm, em: orm.em as unknown as EntityManager, schema, prefix, tables };
  }

  it('ensureAuthzSchema creates the schema and the tables in it; nothing in the default one', async () => {
    const { orm, em, schema, prefix, tables } = await fresh();
    await ensureAuthzSchema(em);
    await ensureAuthzSchema(em); // a second boot is a no-op
    expect(await authzSchemaSql(em)).toBe('');
    expect(await tablesIn(orm, schema, prefix)).toEqual(Object.values(tables).sort());
    expect(await tablesIn(orm, home(), prefix)).toEqual([]);
  });

  it('the heal restores a missing column and index inside the schema', async () => {
    const { orm, em, schema, tables } = await fresh();
    await ensureAuthzSchema(em);
    const q = (id: string) => (dialect === 'mysql' ? `\`${id}\`` : `"${id}"`);
    const connection = orm.em.getConnection();
    await connection.execute(
      `alter table ${q(schema)}.${q(tables.roles)} drop column ${q('guard')}`,
    );
    await connection.execute(
      dialect === 'mysql'
        ? `drop index ${q(`${tables.userRole}_user_idx`)} on ${q(schema)}.${q(tables.userRole)}`
        : `drop index ${q(schema)}.${q(`${tables.userRole}_user_idx`)}`,
    );
    expect(await authzSchemaSql(em)).not.toBe('');
    await ensureAuthzSchema(em);
    expect(await authzSchemaSql(em)).toBe('');
    const columns = (await connection.execute(
      'select column_name as c from information_schema.columns where table_schema = ? and table_name = ?',
      [schema, tables.roles],
    )) as Array<Record<string, string>>;
    expect(columns.map((r) => r.c ?? r.C ?? r.COLUMN_NAME)).toContain('guard');
  });

  it('the store reads and writes in the schema, raw SQL included', async () => {
    const { em } = await fresh();
    const store = new MikroOrmAuthzStore(em);
    await store.ensureSchema();
    const alice = { type: 'user', id: '1' };
    await store.givePermissionToRole('editor', 'posts.publish');
    const acme = dialect === 'mysql' ? {} : { tenantId: 'acme' };
    await store.assignRole(alice, 'editor', acme);
    expect(await store.getRolesForUser(alice, acme)).toEqual(['editor']);
    expect(await store.getPermissionsForUser(alice, acme)).toEqual(['posts.publish']);
    expect(await store.getRolePermissions(['editor'])).toEqual({ editor: ['posts.publish'] });
    await store.setUserRoles(alice, ['viewer'], { source: 'sso' });
    expect((await store.listRoleAssignments({ user: alice })).map((a) => a.role).sort()).toEqual([
      'editor',
      'viewer',
    ]);
    expect(await store.deleteRole('editor')).toBe(true);
  });

  it('works inside an app transaction', async () => {
    const { em } = await fresh();
    await ensureAuthzSchema(em);
    await em.fork().transactional(async (tx) => {
      const store = new MikroOrmAuthzStore(tx as unknown as EntityManager);
      await store.givePermissionToRole('editor', 'posts.publish');
      await store.assignRole({ id: '2' }, 'editor');
      expect(await store.getPermissionsForUser({ id: '2' })).toEqual(['posts.publish']);
    });
  });

  it('the RBAC module boots (creating the schema) and checks in it', async () => {
    const { em } = await fresh();
    const store = new MikroOrmAuthzStore(em);
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
});
