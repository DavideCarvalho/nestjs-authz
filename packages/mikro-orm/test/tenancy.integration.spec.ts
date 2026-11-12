import 'reflect-metadata';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthzModule, CONTEXT_ACCESSOR, Gate } from '@dudousxd/nestjs-authz';
import { MikroORM } from '@mikro-orm/better-sqlite';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthzRbacModule, type AuthzRbacModuleOptions } from '../src/authz-rbac.module.js';
import { AUTHZ_ENTITIES, createAuthzEntitySchemas } from '../src/entities.js';
import { MikroOrmAuthzStore } from '../src/mikro-orm-authz.store.js';
import type { TenantFilter } from '../src/tenancy.js';

const alice = { type: 'user', id: '1' };
const bob = { type: 'user', id: '2' };

async function open(tenantScoped: boolean): Promise<{ orm: MikroORM; store: MikroOrmAuthzStore }> {
  const entities = tenantScoped
    ? createAuthzEntitySchemas({}, { tenantScoped: true }).all
    : AUTHZ_ENTITIES;
  const orm = await MikroORM.init({
    dbName: ':memory:',
    entities: [...entities],
    allowGlobalContext: true,
  });
  const store = new MikroOrmAuthzStore(orm.em);
  await store.ensureSchema();
  return { orm, store };
}

let orm: MikroORM | undefined;
afterEach(async () => {
  await orm?.close(true);
  orm = undefined;
});

describe('MikroORM store: tenant-scoped assignments (tenantScoped: true)', () => {
  it('a tenant role applies in its tenant only; a global one everywhere', async () => {
    const db = await open(true);
    orm = db.orm;
    const { store } = db;
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('viewer', 'posts.read');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.assignRole(alice, 'viewer');

    expect((await store.getRolesForUser(alice, { tenantId: 'acme' })).sort()).toEqual([
      'editor',
      'viewer',
    ]);
    expect(await store.getRolesForUser(alice, { tenantId: 'globex' })).toEqual(['viewer']);
    expect(await store.getRolesForUser(alice)).toEqual(['viewer']);
    expect(await store.userHasPermission(alice, 'posts.publish', { tenantId: 'acme' })).toBe(true);
    expect(await store.userHasPermission(alice, 'posts.publish', { tenantId: 'globex' })).toBe(
      false,
    );
    expect(await store.userHasPermission(alice, 'posts.publish')).toBe(false);
    expect(await store.getUserAuthz(alice, { tenantId: 'acme' })).toEqual({
      roles: expect.arrayContaining(['editor', 'viewer']),
      permissions: expect.arrayContaining(['posts.publish', 'posts.read']),
    });
    expect(await store.getRoleAssignments(alice, { tenantId: 'acme' })).toEqual([
      { role: 'editor', source: 'manual', tenantId: 'acme' },
      { role: 'viewer', source: 'manual', tenantId: null },
    ]);
  });

  it('the same role in two tenants, set and removed per tenant', async () => {
    const db = await open(true);
    orm = db.orm;
    const { store } = db;
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.assignRole(alice, 'editor', { tenantId: 'globex' });
    await store.assignRole(alice, 'editor', { tenantId: 'acme' }); // idempotent
    expect(await store.listRoleAssignments({ user: alice })).toEqual([
      { userType: 'user', userId: '1', role: 'editor', source: 'manual', tenantId: 'acme' },
      { userType: 'user', userId: '1', role: 'editor', source: 'manual', tenantId: 'globex' },
    ]);
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toHaveLength(1);
    expect(await store.listRoleAssignments({ tenantId: null })).toEqual([]);

    await store.removeRole(alice, 'editor'); // global only: none
    expect(await store.listRoleAssignments({ user: alice })).toHaveLength(2);
    await store.removeRole(alice, 'editor', { tenantId: 'acme' });
    expect(await store.getRolesForUser(alice, { tenantId: 'acme' })).toEqual([]);
    expect(await store.getRolesForUser(alice, { tenantId: 'globex' })).toEqual(['editor']);

    await store.setUserRoles(alice, ['viewer', 'editor'], { tenantId: 'globex' });
    await store.setUserRoles(alice, ['owner']);
    expect((await store.getRolesForUser(alice, { tenantId: 'globex' })).sort()).toEqual([
      'editor',
      'owner',
      'viewer',
    ]);
    await store.removeUser(alice);
    expect(await store.listRoleAssignments({ user: alice })).toEqual([]);
  });

  it('ensureSchema adds the tenantId column to an existing table; old rows stay global', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'authz-tenancy-'));
    const dbName = join(dir, 'authz.sqlite');
    try {
      const legacy = await MikroORM.init({
        dbName,
        entities: [...AUTHZ_ENTITIES],
        allowGlobalContext: true,
      });
      const legacyStore = new MikroOrmAuthzStore(legacy.em);
      await legacyStore.ensureSchema();
      await legacyStore.assignRole(alice, 'editor');
      await legacy.close(true);

      const db = await MikroORM.init({
        dbName,
        entities: [...createAuthzEntitySchemas({}, { tenantScoped: true }).all],
        allowGlobalContext: true,
      });
      orm = db;
      const store = new MikroOrmAuthzStore(db.em);
      await store.ensureSchema();
      await store.assignRole(alice, 'viewer', { tenantId: 'acme' });
      expect(await store.getRoleAssignments(alice, { tenantId: 'acme' })).toEqual([
        { role: 'editor', source: 'manual', tenantId: null },
        { role: 'viewer', source: 'manual', tenantId: 'acme' },
      ]);
    } finally {
      await orm?.close(true);
      orm = undefined;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('MikroORM store: without tenantScoped every assignment stays global', () => {
  it('reads ignore the tenant; a tenant-scoped write throws an actionable error', async () => {
    const db = await open(false);
    orm = db.orm;
    const { store } = db;
    await store.assignRole(alice, 'editor');
    expect(await store.getRolesForUser(alice, { tenantId: 'acme' })).toEqual(['editor']);
    await expect(store.assignRole(alice, 'editor', { tenantId: 'acme' })).rejects.toThrow(
      /tenantScoped: true/,
    );
    await expect(store.setUserRoles(alice, [], { tenantId: 'acme' })).rejects.toThrow(
      /tenantScoped: true/,
    );
    await store.removeRole(alice, 'editor', { tenantId: 'acme' }); // nothing to remove
    expect(await store.getRolesForUser(alice)).toEqual(['editor']);
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toEqual([]);
    expect(await store.listRoleAssignments({ tenantId: null })).toHaveLength(1);
  });
});

function tenancyContext(enabled: boolean) {
  let filter: TenantFilter = { mode: 'system' };
  let user: { type: string; id: string } | undefined;
  let store: object = {};
  return {
    accessor: {
      userRef: () => user,
      tenantId: () => (filter.mode === 'tenant' ? filter.tenant.id : undefined),
      get: () => store,
      tenancy: () => ({ enabled }),
      tenantFilter: () => filter,
    },
    set(next: TenantFilter, as?: { type: string; id: string }) {
      filter = next;
      user = as;
      store = {};
    },
  };
}

const tenant = (id: string, role?: string): TenantFilter => ({
  mode: 'tenant',
  tenant: { id, kind: 'organization', source: 'app', ...(role ? { role } : {}) },
});

describe('MikroORM RBAC module: tenancy', () => {
  async function boot(
    store: MikroOrmAuthzStore,
    ctx: ReturnType<typeof tenancyContext>,
    extra: Partial<AuthzRbacModuleOptions> = {},
  ) {
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({ store, autoCreateSchema: false, ...extra }),
      ],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: ctx.accessor }],
    }).compile();
    await moduleRef.init();
    const gate = moduleRef.get(Gate);
    const can = (u: object, permission: string) =>
      gate
        .forUser(u)
        .allows(permission)
        .catch(() => false);
    return { moduleRef, gate, can };
  }

  it('scopes checks by the context tenant like drizzle/typeorm', async () => {
    const db = await open(true);
    orm = db.orm;
    await db.store.givePermissionToRole('editor', 'posts.publish');
    await db.store.assignRole(alice, 'editor', { tenantId: 'acme' });
    const ctx = tenancyContext(true);
    const { moduleRef, can, gate } = await boot(db.store, ctx);

    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(true);
    expect(await gate.forUser(alice).hasRole('editor')).toBe(true);
    ctx.set(tenant('globex'));
    expect(await can(alice, 'posts.publish')).toBe(false);
    ctx.set({ mode: 'tenantless' });
    expect(await can(alice, 'posts.publish')).toBe(false);
    await moduleRef.close();
  });

  it('tenancy off: identical to before (global only, the context tenant is not read)', async () => {
    const db = await open(true);
    orm = db.orm;
    await db.store.givePermissionToRole('editor', 'posts.publish');
    await db.store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await db.store.givePermissionToRole('viewer', 'posts.read');
    await db.store.assignRole(alice, 'viewer');
    const ctx = tenancyContext(false);
    const { moduleRef, can } = await boot(db.store, ctx);
    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(false);
    expect(await can(alice, 'posts.read')).toBe(true);
    await moduleRef.close();
  });

  it('tenancy.roles and an explicit resolver, with the default (global) schema', async () => {
    const db = await open(false);
    orm = db.orm;
    await db.store.givePermissionToRole('org_admin', 'billing.manage');
    const ctx = tenancyContext(true);
    const { moduleRef, can } = await boot(db.store, ctx, {
      tenancy: { roles: { owner: 'org_admin' } },
    });
    ctx.set(tenant('acme', 'owner'), alice);
    expect(await can(alice, 'billing.manage')).toBe(true);
    expect(await can(bob, 'billing.manage')).toBe(false);
    ctx.set(tenant('acme', 'member'), alice);
    expect(await can(alice, 'billing.manage')).toBe(false);
    await moduleRef.close();

    const explicit = await boot(db.store, ctx, {
      tenancy: { roles: { owner: 'org_admin' } },
      tenant: () => 'globex',
    });
    ctx.set(tenant('acme', 'owner'), alice);
    expect(await explicit.can(alice, 'billing.manage')).toBe(false);
    await explicit.moduleRef.close();
  });
});
