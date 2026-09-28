import 'reflect-metadata';
import type { DataSource } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { ensureAuthzSchema } from '../src/schema.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
  targetDialect,
} from './support/datasource.js';

const sorted = <T extends { role: string; source: string }>(rows: T[]) =>
  [...rows].sort((a, b) => `${a.role}|${a.source}`.localeCompare(`${b.role}|${b.source}`));

describeIntegration(`per-source role assignments (${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let ds: DataSource;
  let store: TypeOrmAuthzStore;

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    ds = fx.ds;
    store = new TypeOrmAuthzStore(ds, fx.options);
    await store.ensureSchema();
    await store.givePermissionToRole('editor', 'posts.edit');
  });

  afterEach(async () => {
    await ds.destroy();
  });

  it('assignRole records the default "manual" source', async () => {
    await store.assignRole(1, 'editor');
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
  });

  it('setUserRoles replaces only that source; a role from two sources is kept', async () => {
    await store.assignRole(1, 'editor');
    await store.setUserRoles(1, ['editor', 'viewer'], { source: 'sso' });
    expect(sorted(await store.getRoleAssignments(1))).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
      { role: 'editor', source: 'sso', tenantId: null },
      { role: 'viewer', source: 'sso', tenantId: null },
    ]);
    expect((await store.getRolesForUser(1)).sort()).toEqual(['editor', 'viewer']);

    await store.setUserRoles(1, ['viewer'], { source: 'sso' });
    expect(sorted(await store.getRoleAssignments(1))).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
      { role: 'viewer', source: 'sso', tenantId: null },
    ]);
    // Still an editor through the manual assignment.
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(true);

    await store.setUserRoles(1, [], { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
  });

  it('setUserRoles without a source replaces the manual assignments', async () => {
    await store.setUserRoles(1, ['editor'], { source: 'scim' });
    await store.setUserRoles(1, ['viewer']);
    expect(sorted(await store.getRoleAssignments(1))).toEqual([
      { role: 'editor', source: 'scim', tenantId: null },
      { role: 'viewer', source: 'manual', tenantId: null },
    ]);
  });

  it('removeRole: with a source removes that one, without removes every source', async () => {
    await store.assignRole(1, 'editor');
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.removeRole(1, 'editor', { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);
    await store.assignRole(1, 'editor', { source: 'sso' });
    await store.removeRole(1, 'editor');
    expect(await store.getRoleAssignments(1)).toEqual([]);
  });

  it('setUserRoles is tenant-scoped', async () => {
    await store.setUserRoles(1, ['editor'], { source: 'sso' }); // global
    await store.setUserRoles(1, ['viewer'], { source: 'sso', tenantId: 'acme' });
    await store.setUserRoles(1, [], { source: 'sso', tenantId: 'acme' });
    expect(await store.getRoleAssignments(1, { tenantId: 'acme' })).toEqual([
      { role: 'editor', source: 'sso', tenantId: null },
    ]);
    await store.setUserRoles(1, ['viewer'], { source: 'sso', tenantId: 'acme' });
    expect(sorted(await store.getRoleAssignments(1, { tenantId: 'acme' }))).toEqual([
      { role: 'editor', source: 'sso', tenantId: null },
      { role: 'viewer', source: 'sso', tenantId: 'acme' },
    ]);
    // Unscoped reads never see the tenant's rows.
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'sso', tenantId: null },
    ]);
  });

  it('self-heals a pre-source user_role table; the README PK migration enables two sources', async () => {
    await store.assignRole(1, 'editor');
    const qr = ds.createQueryRunner();
    await qr.dropColumn(fx.names.userRole, 'source');
    expect((await qr.getTable(fx.names.userRole))?.findColumnByName('source')).toBeUndefined();
    await qr.release();

    await ensureAuthzSchema(ds, fx.options);
    const healed = ds.createQueryRunner();
    const table = await healed.getTable(fx.names.userRole);
    await healed.release();
    expect(table?.findColumnByName('source')?.isPrimary).toBe(false); // PK untouched
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);

    if (fx.dialect === 'sqlite') return; // SQLite can't alter a PK in place (table rebuild).
    const t = ds.driver.escape(fx.names.userRole);
    const cols = ['userType', 'userId', 'roleId', 'tenantId', 'source'].map((c) =>
      ds.driver.escape(c),
    );
    if (fx.dialect === 'mysql') {
      // utf8mb4: shrink the new key columns so the 5-column PK fits the 3072-byte limit.
      await ds.query(
        `ALTER TABLE ${t} MODIFY ${cols[2]} varchar(64) NOT NULL, MODIFY ${cols[4]} varchar(64) NOT NULL DEFAULT 'manual', DROP PRIMARY KEY, ADD PRIMARY KEY (${cols.join(', ')})`,
      );
    } else {
      const [{ name }] = (await ds.query(
        `SELECT conname AS name FROM pg_constraint WHERE conrelid = '${fx.names.userRole}'::regclass AND contype = 'p'`,
      )) as Array<{ name: string }>;
      await ds.query(
        `ALTER TABLE ${t} DROP CONSTRAINT "${name}", ADD PRIMARY KEY (${cols.join(', ')})`,
      );
    }
    await store.assignRole(1, 'editor', { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toHaveLength(2);
  });
});
