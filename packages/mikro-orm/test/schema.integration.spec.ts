import 'reflect-metadata';
import { MikroORM } from '@mikro-orm/better-sqlite';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AUTHZ_ENTITIES, RoleEntity } from '../src/entities.js';
import { MikroOrmAuthzStore } from '../src/mikro-orm-authz.store.js';
import { AuthzRoleRepository } from '../src/repositories.js';
import { authzSchemaSql, ensureAuthzSchema } from '../src/schema.js';

async function freshOrm(): Promise<MikroORM> {
  return MikroORM.init({
    dbName: ':memory:',
    entities: [...AUTHZ_ENTITIES],
    allowGlobalContext: true,
  });
}

describe('ensureAuthzSchema (integration, sqlite)', () => {
  let orm: MikroORM;

  beforeEach(async () => {
    orm = await freshOrm();
  });

  afterEach(async () => {
    await orm.close(true);
  });

  it('registering AUTHZ_ENTITIES binds the custom repositories', () => {
    expect(orm.em.getRepository(RoleEntity)).toBeInstanceOf(AuthzRoleRepository);
  });

  it('produces non-destructive SQL and creates all four tables, idempotently', async () => {
    const sql = await authzSchemaSql(orm);
    expect(sql).toMatch(/create table/i);
    expect(sql).toMatch(/authz_roles/i);
    expect(sql).not.toMatch(/drop table/i);

    await ensureAuthzSchema(orm);
    await ensureAuthzSchema(orm); // idempotent

    const conn = orm.em.getConnection();
    for (const t of [
      'authz_roles',
      'authz_permissions',
      'authz_role_permission',
      'authz_user_role',
    ]) {
      const rows = await conn.execute(
        `SELECT name FROM sqlite_master WHERE type='table' AND name = '${t}'`,
      );
      expect(rows).toHaveLength(1);
    }
  });

  it('non-destructively adds a column missing from an existing table, keeping data intact', async () => {
    const store = new MikroOrmAuthzStore(orm.em);
    await ensureAuthzSchema(orm);
    await store.givePermissionToRole('editor', 'posts.publish');

    const conn = orm.em.getConnection();
    // Simulate an older deployment missing the nullable `guard` column on authz_roles.
    await conn.execute('ALTER TABLE authz_roles DROP COLUMN guard');
    const colsBefore = (await conn.execute('PRAGMA table_info(authz_roles)')) as Array<{
      name: string;
    }>;
    expect(colsBefore.some((c) => c.name === 'guard')).toBe(false);
    const rowsBefore = await conn.execute('SELECT id, name FROM authz_roles');
    expect(rowsBefore).toHaveLength(1);

    // ensureAuthzSchema must ADD the missing column without recreating/wiping the table.
    await ensureAuthzSchema(orm);
    await ensureAuthzSchema(orm); // idempotent once the column is back

    const colsAfter = (await conn.execute('PRAGMA table_info(authz_roles)')) as Array<{
      name: string;
      notnull: number;
    }>;
    const guardCol = colsAfter.find((c) => c.name === 'guard');
    expect(guardCol).toBeDefined();
    expect(guardCol?.notnull).toBe(0); // nullable
    const rowsAfter = (await conn.execute('SELECT id, name, guard FROM authz_roles')) as Array<{
      guard: string | null;
    }>;
    expect(rowsAfter).toHaveLength(1); // pre-existing data untouched
    expect(rowsAfter[0]?.guard).toBeNull();

    // The store still resolves the persisted grant after the self-heal.
    await store.assignRole(1, 'editor');
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(true);
  });

  it('authzSchemaSql is empty once the schema is current (migration helper)', async () => {
    await ensureAuthzSchema(orm);
    const sql = await authzSchemaSql(orm);
    expect(sql).toBe('');
  });
});
