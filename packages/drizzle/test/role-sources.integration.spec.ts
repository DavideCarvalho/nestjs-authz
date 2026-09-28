import 'reflect-metadata';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { DrizzleAuthzStore } from '../src/drizzle-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDb,
  targetDialect,
} from './support/db.js';

const sorted = <T extends { role: string; source: string }>(rows: T[]) =>
  [...rows].sort((a, b) => `${a.role}|${a.source}`.localeCompare(`${b.role}|${b.source}`));

describeIntegration(`per-source role assignments (${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let store: DrizzleAuthzStore;

  beforeEach(async () => {
    fx = await freshAuthzDb();
    store = new DrizzleAuthzStore(fx.db, fx.options);
    await store.ensureSchema();
    await store.givePermissionToRole('editor', 'posts.edit');
  });

  afterEach(async () => {
    await fx.close();
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

  it('self-heals a pre-source user_role table; the documented PK migration enables two sources', async () => {
    await store.assignRole(1, 'editor');
    const t = `"${fx.names.userRole}"`;
    await fx.query(`ALTER TABLE ${t} DROP CONSTRAINT "${fx.names.userRole}_pkey"`);
    await fx.query(`ALTER TABLE ${t} DROP COLUMN "source"`);
    await fx.query(
      `ALTER TABLE ${t} ADD CONSTRAINT "${fx.names.userRole}_pkey" PRIMARY KEY ("userType","userId","roleId","tenantId")`,
    );

    await store.ensureSchema(); // adds "source" (existing rows → 'manual')
    expect(await store.getRoleAssignments(1)).toEqual([
      { role: 'editor', source: 'manual', tenantId: null },
    ]);

    // README migration: widen the primary key to include "source".
    await fx.query(
      `ALTER TABLE ${t} DROP CONSTRAINT "${fx.names.userRole}_pkey", ADD CONSTRAINT "${fx.names.userRole}_pkey" PRIMARY KEY ("userType","userId","roleId","tenantId","source")`,
    );
    await store.assignRole(1, 'editor', { source: 'sso' });
    expect(await store.getRoleAssignments(1)).toHaveLength(2);
  });
});
