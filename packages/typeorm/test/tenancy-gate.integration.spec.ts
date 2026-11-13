import 'reflect-metadata';
import {
  type AuthzDevTool,
  AuthzModule,
  CONTEXT_ACCESSOR,
  DEV_TOOLS_SLOT,
  Gate,
} from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { AuthzRbacModule, type AuthzRbacModuleOptions } from '../src/authz-rbac.module.js';
import type { TenantFilter } from '../src/tenancy.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
  targetDialect,
} from './support/datasource.js';

/**
 * A structural nestjs-context accessor with the tenancy methods. Every `set` starts a fresh
 * request store, so the request-scoped permission cache never carries over between checks.
 */
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

describeIntegration(`RBAC tenancy (context tenancy contract, ${targetDialect()})`, () => {
  let fx: AuthzFixture;
  let store: TypeOrmAuthzStore;
  const alice = { type: 'user', id: '1' };
  const bob = { type: 'user', id: '2' };

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    store = new TypeOrmAuthzStore(fx.ds, fx.options);
    await store.ensureSchema();
    await store.givePermissionToRole('editor', 'posts.publish');
    await store.givePermissionToRole('org_admin', 'billing.manage');
    await store.assignRole(alice, 'editor', { tenantId: 'acme' });
  });

  afterEach(async () => {
    await fx.ds.destroy();
  });

  async function boot(
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
    const can = (user: object, permission: string) =>
      gate
        .forUser(user)
        .allows(permission)
        .catch(() => false);
    return { moduleRef, gate, can };
  }

  it('tenant mode: a tenant-scoped role grants only in its tenant; other modes see globals', async () => {
    const ctx = tenancyContext(true);
    const { moduleRef, can, gate } = await boot(ctx);

    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(true);
    expect(await gate.forUser(alice).hasRole('editor')).toBe(true);
    ctx.set(tenant('globex'));
    expect(await can(alice, 'posts.publish')).toBe(false);
    ctx.set({ mode: 'tenantless' });
    expect(await can(alice, 'posts.publish')).toBe(false);
    ctx.set({ mode: 'all' });
    expect(await can(alice, 'posts.publish')).toBe(false);
    ctx.set({ mode: 'system' });
    expect(await can(alice, 'posts.publish')).toBe(false);

    await store.assignRole(alice, 'editor'); // global: applies everywhere
    ctx.set({ mode: 'tenantless' });
    expect(await can(alice, 'posts.publish')).toBe(true);
    await moduleRef.close();
  });

  it('tenancy off: identical to before (the plain tenantId scopes)', async () => {
    const ctx = tenancyContext(false);
    const { moduleRef, can } = await boot(ctx);
    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(true);
    ctx.set(tenant('globex'));
    expect(await can(alice, 'posts.publish')).toBe(false);
    await moduleRef.close();
  });

  it('tenancy.roles maps the caller tenant role to roles in that tenant only', async () => {
    const ctx = tenancyContext(true);
    const { moduleRef, can, gate } = await boot(ctx, {
      tenancy: { roles: { owner: 'org_admin', member: 'org_member' } },
    });

    ctx.set(tenant('acme', 'owner'), alice);
    expect(await can(alice, 'billing.manage')).toBe(true);
    expect(await gate.forUser(alice).hasRole('org_admin')).toBe(true);
    // The caller's tenant role is not someone else's.
    expect(await can(bob, 'billing.manage')).toBe(false);

    ctx.set(tenant('acme', 'member'), alice);
    expect(await can(alice, 'billing.manage')).toBe(false);
    expect(await gate.forUser(alice).hasRole('org_member')).toBe(true);

    ctx.set(tenant('acme', 'guest'), alice);
    expect(await can(alice, 'billing.manage')).toBe(false);
    await moduleRef.close();
  });

  it('an explicit tenant resolver wins over the context tenant', async () => {
    const ctx = tenancyContext(true);
    const { moduleRef, can } = await boot(ctx, {
      tenant: (user) => (user as { org?: string }).org,
      tenancy: { roles: { owner: 'org_admin' } },
    });

    ctx.set(tenant('globex', 'owner'), alice);
    // The resolver says acme: the acme role applies, globex's mapped role does not.
    expect(await can({ ...alice, org: 'acme' }, 'posts.publish')).toBe(true);
    expect(await can({ ...alice, org: 'acme' }, 'billing.manage')).toBe(false);
    // No answer from the resolver: back to the context tenant (globex). New request, so the
    // request-scoped permission cache starts empty.
    ctx.set(tenant('globex', 'owner'), alice);
    expect(await can(alice, 'posts.publish')).toBe(false);
    expect(await can(alice, 'billing.manage')).toBe(true);
    await moduleRef.close();
  });

  it('tenancy: false keeps the module out even when the context enables it', async () => {
    const ctx = tenancyContext(true);
    const { moduleRef, can } = await boot(ctx, {
      tenancy: false,
    });
    ctx.set({ mode: 'all' });
    expect(await can(alice, 'posts.publish')).toBe(false);
    ctx.set(tenant('acme'));
    expect(await can(alice, 'posts.publish')).toBe(true); // via the plain tenantId
    await moduleRef.close();
  });
  it('the dev tools explain a check in any tenant from the real store', async () => {
    delete (globalThis as Record<symbol, unknown>)[DEV_TOOLS_SLOT];
    await store.giveUserPermission(alice, 'reports.view');
    const ctx = tenancyContext(true);
    const { moduleRef } = await boot(ctx, { tenancy: { roles: { owner: 'org_admin' } } });
    const tools = (
      (globalThis as Record<symbol, { libs: Array<{ lib: string; tools: AuthzDevTool[] }> }>)[
        DEV_TOOLS_SLOT
      ]?.libs.find((l) => l.lib === 'authz')?.tools ?? []
    ).reduce<Record<string, AuthzDevTool>>((all, t) => {
      all[t.name] = t;
      return all;
    }, {});
    const explain = tools.authz_explain_check as AuthzDevTool;

    // The request is in globex; the tool asks about acme.
    ctx.set(tenant('globex', 'owner'), alice);
    expect(
      await explain.run({ subjectId: '1', permission: 'posts.publish', tenantId: 'acme' }),
    ).toMatchObject({
      allowed: true,
      reason: 'permission-provider',
      tenant: { id: 'acme', from: 'explicit' },
      effectiveRoles: ['editor'],
      roleSources: { editor: ['store'] },
      grantingRoles: [{ role: 'editor', matched: ['posts.publish'] }],
      directGrants: [],
    });
    // Without tenantId: the request's own scope, where the caller's owner role maps to org_admin.
    expect(await explain.run({ subjectId: '1', permission: 'billing.manage' })).toMatchObject({
      allowed: true,
      tenant: { id: 'globex', from: 'context' },
      roleSources: { org_admin: ['tenant'] },
      grantingRoles: [{ role: 'org_admin', matched: ['billing.manage'] }],
    });
    expect(
      await explain.run({ subjectId: '1', permission: 'reports.view', tenantId: '' }),
    ).toMatchObject({
      allowed: true,
      tenant: { id: null, from: 'global' },
      directGrants: ['reports.view'],
    });
    expect(
      await tools.authz_list_effective_permissions?.run({ subjectId: '1', tenantId: 'acme' }),
    ).toMatchObject({ items: ['posts.publish', 'reports.view'], next: null });
    await moduleRef.close();
  });
  it('a nested tenant: roles held at the clinic apply in its unit; required throws 403', async () => {
    await store.givePermissionToRole('clinic_admin', 'staff.manage');
    await store.assignRole(alice, 'clinic_admin', { tenantId: 'c1' });
    await store.assignRole(alice, 'editor', { tenantId: 'u1' });
    const ctx = tenancyContext(true);
    const { moduleRef, can, gate } = await boot(ctx, { tenancy: { required: true } });
    const unit: TenantFilter = {
      mode: 'tenant',
      tenant: {
        id: 'u1',
        kind: 'unit',
        source: 'app',
        chain: [
          { id: 'c1', kind: 'clinic' },
          { id: 'u1', kind: 'unit' },
        ],
      },
    };
    ctx.set(unit, alice);
    expect(await can(alice, 'staff.manage')).toBe(true);
    expect(await can(alice, 'posts.publish')).toBe(true);
    // In the clinic itself, the unit's role does not apply.
    ctx.set({ mode: 'tenant', tenant: { id: 'c1', kind: 'clinic', source: 'app' } }, alice);
    expect(await can(alice, 'staff.manage')).toBe(true);
    expect(await can(alice, 'posts.publish')).toBe(false);

    ctx.set({ mode: 'tenantless' }, alice);
    await expect(gate.forUser(alice).allows('staff.manage')).rejects.toMatchObject({
      status: 403,
      code: 'E_TENANT_REQUIRED',
    });
    await moduleRef.close();
  });
});
