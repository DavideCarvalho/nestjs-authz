import 'reflect-metadata';
import type { DataSource } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { createAuthzTables, ensureAuthzSchema } from '../src/schema.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
  targetDialect,
} from './support/datasource.js';

describeIntegration(`ensureAuthzSchema (integration, ${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let ds: DataSource;

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    ds = fx.ds;
  });

  afterEach(async () => {
    await ds.destroy();
  });

  it('creates all five tables on demand, idempotently', async () => {
    const qr = ds.createQueryRunner();
    expect(await qr.hasTable(fx.names.roles)).toBe(false);
    await qr.release();

    await ensureAuthzSchema(ds, fx.options);
    await ensureAuthzSchema(ds, fx.options); // idempotent

    const qr2 = ds.createQueryRunner();
    for (const t of [
      fx.names.roles,
      fx.names.permissions,
      fx.names.rolePermission,
      fx.names.userRole,
      fx.names.userPermission,
    ]) {
      expect(await qr2.hasTable(t)).toBe(true);
    }
    await qr2.release();
  });

  it('non-destructively adds a column missing from an existing table, keeping data intact', async () => {
    const store = new TypeOrmAuthzStore(ds, fx.options);
    await ensureAuthzSchema(ds, fx.options);
    await store.givePermissionToRole('editor', 'posts.publish');

    // Simulate an older deployment missing the nullable `guard` column on the roles table.
    const dropQr = ds.createQueryRunner();
    const before = await dropQr.getTable(fx.names.roles);
    expect(before?.findColumnByName('guard')).toBeDefined();
    await dropQr.dropColumn(fx.names.roles, 'guard');
    const after = await dropQr.getTable(fx.names.roles);
    expect(after?.findColumnByName('guard')).toBeUndefined();
    const rowsBefore = await dropQr.query(
      `SELECT id, name FROM ${ds.driver.escape(fx.names.roles)}`,
    );
    expect(rowsBefore).toHaveLength(1);
    await dropQr.release();

    // ensureAuthzSchema must ADD the missing column without recreating/wiping the table.
    await ensureAuthzSchema(ds, fx.options);
    await ensureAuthzSchema(ds, fx.options); // idempotent once the column is back

    const checkQr = ds.createQueryRunner();
    const repaired = await checkQr.getTable(fx.names.roles);
    const guardCol = repaired?.findColumnByName('guard');
    expect(guardCol).toBeDefined();
    expect(guardCol?.isNullable).toBe(true);
    const rowsAfter = await checkQr.query(
      `SELECT id, name, guard FROM ${ds.driver.escape(fx.names.roles)}`,
    );
    expect(rowsAfter).toHaveLength(1); // pre-existing data untouched
    expect(rowsAfter[0].guard).toBeNull();
    await checkQr.release();

    // The store still resolves the persisted grant after the self-heal.
    await store.assignRole(1, 'editor');
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(true);
  });

  it('self-heals a pre-v1 user_role table missing the post-v1 tenantId column', async () => {
    const store = new TypeOrmAuthzStore(ds, fx.options);
    await ensureAuthzSchema(ds, fx.options);
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.assignRole(1, 'editor'); // global (tenantId = '')
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(true);

    // Simulate an older deployment whose user_role table lacks `tenantId`.
    const dropQr = ds.createQueryRunner();
    await dropQr.dropColumn(fx.names.userRole, 'tenantId');
    const after = await dropQr.getTable(fx.names.userRole);
    expect(after?.findColumnByName('tenantId')).toBeUndefined();
    await dropQr.release();

    // ensureAuthzSchema must ADD the missing column (defaulted), not recreate the table.
    await ensureAuthzSchema(ds, fx.options);
    const checkQr = ds.createQueryRunner();
    const repaired = await checkQr.getTable(fx.names.userRole);
    expect(repaired?.findColumnByName('tenantId')).toBeDefined();
    await checkQr.release();

    // The pre-existing (now defaulted-tenant) assignment still resolves unscoped.
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(true);
    // And a fresh tenant-scoped assignment now works.
    await store.assignRole(2, 'editor', { tenantId: 'acme' });
    expect(await store.userHasPermission(2, 'posts.publish', { tenantId: 'acme' })).toBe(true);
  });

  it('creates the post-v1 user_permission table on demand', async () => {
    await ensureAuthzSchema(ds, fx.options);
    const qr = ds.createQueryRunner();
    expect(await qr.hasTable(fx.names.userPermission)).toBe(true);
    await qr.release();
  });

  it('createAuthzTables works as a migration helper (and is idempotent)', async () => {
    const qr = ds.createQueryRunner();
    try {
      expect(await qr.hasTable(fx.names.roles)).toBe(false);
      await createAuthzTables(qr, fx.options);
      await createAuthzTables(qr, fx.options); // idempotent — skips existing tables
      expect(await qr.hasTable(fx.names.roles)).toBe(true);
      expect(await qr.hasTable(fx.names.userRole)).toBe(true);
    } finally {
      await qr.release();
    }

    // Tables created by the migration helper are usable by the store.
    const store = new TypeOrmAuthzStore(ds, fx.options);
    await store.givePermissionToRole('admin', 'users.manage');
    await store.assignRole(1, 'admin');
    expect(await store.userHasPermission(1, 'users.manage')).toBe(true);
  });
});
