import 'reflect-metadata';
import type { DataSource } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
  targetDialect,
} from './support/datasource.js';

describeIntegration(`direct user permissions (no role required, ${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let ds: DataSource;
  let store: TypeOrmAuthzStore;

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    ds = fx.ds;
    store = new TypeOrmAuthzStore(ds, fx.options);
    await store.ensureSchema();
  });

  afterEach(async () => {
    await ds.destroy();
  });

  it('grants a permission directly to a user, no role involved', async () => {
    await store.giveUserPermission({ type: 'user', id: 7 }, 'posts.publish');

    expect(await store.getRolesForUser({ type: 'user', id: 7 })).toEqual([]);
    expect(await store.getPermissionsForUser({ type: 'user', id: 7 })).toEqual(['posts.publish']);
    expect(await store.userHasPermission({ type: 'user', id: 7 }, 'posts.publish')).toBe(true);
    // A different user gains nothing.
    expect(await store.userHasPermission({ type: 'user', id: 8 }, 'posts.publish')).toBe(false);
  });

  it('unions direct + role-derived permissions, de-duplicated', async () => {
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.assignRole(1, 'editor');
    await store.giveUserPermission(1, 'posts.publish');
    await store.giveUserPermission(1, 'posts.edit'); // also via role → dedup

    expect((await store.getPermissionsForUser(1)).sort()).toEqual(['posts.edit', 'posts.publish']);
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(true);
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(true);
  });

  it('revokeUserPermission removes only the direct grant (role grant survives)', async () => {
    await store.givePermissionToRole('editor', 'posts.edit');
    await store.assignRole(1, 'editor');
    await store.giveUserPermission(1, 'posts.edit'); // direct duplicate of role grant
    await store.giveUserPermission(1, 'posts.publish');

    await store.revokeUserPermission(1, 'posts.publish');
    expect(await store.userHasPermission(1, 'posts.publish')).toBe(false);

    // Revoking the direct grant for posts.edit leaves the role-derived one intact.
    await store.revokeUserPermission(1, 'posts.edit');
    expect(await store.userHasPermission(1, 'posts.edit')).toBe(true);
  });

  it('giveUserPermission is idempotent; revoke of an absent grant is a no-op', async () => {
    await store.giveUserPermission(1, 'posts.publish');
    await store.giveUserPermission(1, 'posts.publish');
    expect(await store.getPermissionsForUser(1)).toEqual(['posts.publish']);
    await store.revokeUserPermission(1, 'ghost.permission'); // no-op
  });
});

describeIntegration(`tenant-scoped role assignments (${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let ds: DataSource;
  let store: TypeOrmAuthzStore;

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    ds = fx.ds;
    store = new TypeOrmAuthzStore(ds, fx.options);
    await store.ensureSchema();
    await store.givePermissionToRole('editor', 'posts.publish');
  });

  afterEach(async () => {
    await ds.destroy();
  });

  it('a tenant-scoped role only applies within that tenant', async () => {
    await store.assignRole({ type: 'user', id: 1 }, 'editor', { tenantId: 'acme' });

    // Within tenant acme → the role (and its permissions) apply.
    expect(await store.getRolesForUser(1, { tenantId: 'acme' })).toEqual(['editor']);
    expect(await store.userHasPermission(1, 'posts.publish', { tenantId: 'acme' })).toBe(true);

    // In a different tenant → not applicable.
    expect(await store.getRolesForUser(1, { tenantId: 'globex' })).toEqual([]);
    expect(await store.userHasPermission(1, 'posts.publish', { tenantId: 'globex' })).toBe(false);

    // With NO tenant context → a tenant-scoped role still does not apply (it is
    // bound to acme), so an unscoped check sees nothing.
    expect(await store.getRolesForUser(1)).toEqual([]);
  });

  it('a global (untenanted) role applies in every tenant AND with no tenant', async () => {
    await store.assignRole(1, 'editor'); // no tenant → global

    expect(await store.getRolesForUser(1)).toEqual(['editor']);
    expect(await store.getRolesForUser(1, { tenantId: 'acme' })).toEqual(['editor']);
    expect(await store.userHasPermission(1, 'posts.publish', { tenantId: 'globex' })).toBe(true);
  });

  it('removeRole respects tenant scope', async () => {
    await store.assignRole(1, 'editor', { tenantId: 'acme' });
    await store.assignRole(1, 'editor', { tenantId: 'globex' });

    await store.removeRole(1, 'editor', { tenantId: 'acme' });
    expect(await store.getRolesForUser(1, { tenantId: 'acme' })).toEqual([]);
    expect(await store.getRolesForUser(1, { tenantId: 'globex' })).toEqual(['editor']);
  });

  it('same user can hold the same role in two tenants (idempotent per tenant)', async () => {
    await store.assignRole(1, 'editor', { tenantId: 'acme' });
    await store.assignRole(1, 'editor', { tenantId: 'acme' }); // idempotent
    await store.assignRole(1, 'editor', { tenantId: 'globex' });

    expect(await store.getRolesForUser(1, { tenantId: 'acme' })).toEqual(['editor']);
    expect(await store.getRolesForUser(1, { tenantId: 'globex' })).toEqual(['editor']);
  });
});
