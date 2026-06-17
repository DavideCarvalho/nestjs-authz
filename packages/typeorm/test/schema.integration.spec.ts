import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AUTHZ_ENTITIES } from '../src/entities.js';
import { createAuthzTables, ensureAuthzSchema } from '../src/schema.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';

async function freshDataSource(): Promise<DataSource> {
  const ds = new DataSource({
    type: 'sqlite',
    database: ':memory:',
    entities: [...AUTHZ_ENTITIES],
    synchronize: false,
  });
  await ds.initialize();
  return ds;
}

describe('ensureAuthzSchema (integration, sqlite)', () => {
  let ds: DataSource;

  beforeEach(async () => {
    ds = await freshDataSource();
  });

  afterEach(async () => {
    await ds.destroy();
  });

  it('creates all four tables on demand, idempotently', async () => {
    const qr = ds.createQueryRunner();
    expect(await qr.hasTable('authz_roles')).toBe(false);
    await qr.release();

    await ensureAuthzSchema(ds);
    await ensureAuthzSchema(ds); // idempotent

    const qr2 = ds.createQueryRunner();
    for (const t of [
      'authz_roles',
      'authz_permissions',
      'authz_role_permission',
      'authz_user_role',
    ]) {
      expect(await qr2.hasTable(t)).toBe(true);
    }
    await qr2.release();
  });

  it('non-destructively adds a column missing from an existing table, keeping data intact', async () => {
    const store = new TypeOrmAuthzStore(ds);
    await ensureAuthzSchema(ds);
    await store.givePermissionToRole('editor', 'posts.publish');

    // Simulate an older deployment missing the nullable `guard` column on authz_roles.
    const dropQr = ds.createQueryRunner();
    const before = await dropQr.getTable('authz_roles');
    expect(before?.findColumnByName('guard')).toBeDefined();
    await dropQr.dropColumn('authz_roles', 'guard');
    const after = await dropQr.getTable('authz_roles');
    expect(after?.findColumnByName('guard')).toBeUndefined();
    const rowsBefore = await dropQr.query('SELECT id, name FROM authz_roles');
    expect(rowsBefore).toHaveLength(1);
    await dropQr.release();

    // ensureAuthzSchema must ADD the missing column without recreating/wiping the table.
    await ensureAuthzSchema(ds);
    await ensureAuthzSchema(ds); // idempotent once the column is back

    const checkQr = ds.createQueryRunner();
    const repaired = await checkQr.getTable('authz_roles');
    const guardCol = repaired?.findColumnByName('guard');
    expect(guardCol).toBeDefined();
    expect(guardCol?.isNullable).toBe(true);
    const rowsAfter = await checkQr.query('SELECT id, name, guard FROM authz_roles');
    expect(rowsAfter).toHaveLength(1); // pre-existing data untouched
    expect(rowsAfter[0].guard).toBeNull();
    await checkQr.release();

    // The store still resolves the persisted grant after the self-heal.
    await store.assignRole(1, 'editor');
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(true);
  });

  it('createAuthzTables works as a migration helper (and is idempotent)', async () => {
    const qr = ds.createQueryRunner();
    try {
      expect(await qr.hasTable('authz_roles')).toBe(false);
      await createAuthzTables(qr);
      await createAuthzTables(qr); // idempotent — skips existing tables
      expect(await qr.hasTable('authz_roles')).toBe(true);
      expect(await qr.hasTable('authz_user_role')).toBe(true);
    } finally {
      await qr.release();
    }

    // Tables created by the migration helper are usable by the store.
    const store = new TypeOrmAuthzStore(ds);
    await store.givePermissionToRole('admin', 'users.manage');
    await store.assignRole(1, 'admin');
    expect(await store.userHasPermission(1, 'users.manage')).toBe(true);
  });
});
