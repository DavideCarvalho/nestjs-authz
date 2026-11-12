import 'reflect-metadata';
import { AuthzModule, CONTEXT_ACCESSOR, Gate } from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { AuthzRbacModule, type AuthzRbacModuleOptions } from '../src/authz-rbac.module.js';
import { PrismaAuthzStore } from '../src/prisma-authz.store.js';
import type { PrismaAuthzClientLike } from '../src/prisma-client.js';
import type { TenantFilter } from '../src/tenancy.js';
import { makeFakeClient } from './fake-client.js';

const alice = { type: 'user', id: '1' };
const bob = { type: 'user', id: '2' };

describe.each([
  ['raw fast path', true],
  ['three-query path', false],
] as const)('PrismaAuthzStore tenantScoped (%s)', (_name, rawQuery) => {
  const make = () => {
    const client = makeFakeClient({ rawQuery });
    return { client, store: new PrismaAuthzStore(client, { tenantScoped: true }) };
  };

  it('a tenant role applies in its tenant only; a global one everywhere', async () => {
    const { store } = make();
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
    expect(await store.getRoleAssignments(alice, { tenantId: 'acme' })).toEqual([
      { role: 'editor', source: 'manual', tenantId: 'acme' },
      { role: 'viewer', source: 'manual', tenantId: null },
    ]);
  });

  it('assign, list, set and remove per tenant', async () => {
    const { store } = make();
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    await store.assignRole(alice, 'editor', { tenantId: 'globex' });
    await store.assignRole(alice, 'editor', { tenantId: 'acme' }); // idempotent
    expect(await store.listRoleAssignments({ user: alice })).toEqual([
      { userType: 'user', userId: '1', role: 'editor', source: 'manual', tenantId: 'acme' },
      { userType: 'user', userId: '1', role: 'editor', source: 'manual', tenantId: 'globex' },
    ]);
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toHaveLength(1);
    expect(await store.listRoleAssignments({ tenantId: null })).toEqual([]);

    await store.removeRole(alice, 'editor'); // the global assignment: there is none
    expect(await store.listRoleAssignments({ user: alice })).toHaveLength(2);
    await store.removeRole(alice, 'editor', { tenantId: 'acme' });
    expect(await store.getRolesForUser(alice, { tenantId: 'acme' })).toEqual([]);

    await store.setUserRoles(alice, ['viewer'], { tenantId: 'globex' });
    expect(await store.getRolesForUser(alice, { tenantId: 'globex' })).toEqual(['viewer']);
  });
});

describe('PrismaAuthzStore without tenantScoped (default)', () => {
  it('never sends tenantId; reads ignore the tenant; a tenant write throws', async () => {
    const client = makeFakeClient();
    const store = new PrismaAuthzStore(client);
    await store.assignRole(alice, 'editor');
    expect(client.userRole as unknown as { rows: object[] }).toMatchObject({
      rows: [{ userType: 'user', userId: '1' }],
    });
    expect('tenantId' in (client.userRole as unknown as { rows: object[] }).rows[0]!).toBe(false);
    expect(await store.getRolesForUser(alice, { tenantId: 'acme' })).toEqual(['editor']);
    await expect(store.assignRole(alice, 'editor', { tenantId: 'acme' })).rejects.toThrow(
      /tenantScoped: true/,
    );
    await store.removeRole(alice, 'editor', { tenantId: 'acme' }); // nothing to remove
    expect(await store.getRolesForUser(alice)).toEqual(['editor']);
    expect(await store.listRoleAssignments({ tenantId: 'acme' })).toEqual([]);
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

describe('Prisma RBAC module: tenancy', () => {
  async function boot(
    client: PrismaAuthzClientLike,
    ctx: ReturnType<typeof tenancyContext>,
    extra: Partial<AuthzRbacModuleOptions> = {},
  ) {
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({ client, ...extra }),
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

  async function seeded() {
    const client = makeFakeClient();
    const store = new PrismaAuthzStore(client, { tenantScoped: true });
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('org_admin', 'billing.manage');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
    return client;
  }

  it('scopes checks by the context tenant like drizzle/typeorm', async () => {
    const ctx = tenancyContext(true);
    const { moduleRef, can, gate } = await boot(await seeded(), ctx, { tenantScoped: true });
    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(true);
    expect(await gate.forUser(alice).hasRole('editor')).toBe(true);
    ctx.set(tenant('globex'));
    expect(await can(alice, 'posts.publish')).toBe(false);
    ctx.set({ mode: 'all' });
    expect(await can(alice, 'posts.publish')).toBe(false);
    await moduleRef.close();
  });

  it('tenancy off: identical to before (the context tenant is not read)', async () => {
    const ctx = tenancyContext(false);
    const { moduleRef, can } = await boot(await seeded(), ctx, { tenantScoped: true });
    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(false);
    await moduleRef.close();
  });

  it('tenancy.roles grants the mapped role to the caller only; an explicit resolver wins', async () => {
    const client = await seeded();
    const ctx = tenancyContext(true);
    const app = await boot(client, ctx, {
      tenantScoped: true,
      tenancy: { roles: { owner: 'org_admin' } },
    });
    ctx.set(tenant('acme', 'owner'), alice);
    expect(await app.can(alice, 'billing.manage')).toBe(true);
    expect(await app.can(bob, 'billing.manage')).toBe(false);
    await app.moduleRef.close();

    const explicit = await boot(client, ctx, {
      tenantScoped: true,
      tenancy: { roles: { owner: 'org_admin' } },
      tenant: () => 'globex',
    });
    ctx.set(tenant('acme', 'owner'), alice);
    expect(await explicit.can(alice, 'billing.manage')).toBe(false);
    expect(await explicit.can(alice, 'posts.publish')).toBe(false);
    await explicit.moduleRef.close();
  });
});
