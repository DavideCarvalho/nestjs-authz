import { readFileSync } from 'node:fs';
import { runInTenantScope, runWithoutRequiredTenant } from '@dudousxd/nestjs-authz';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type AuthzTenancyOption,
  type TenantContextAccessor,
  type TenantFilter,
  TenantRequiredError,
  resolveRbacTenant,
} from '../src/tenancy.js';

const SLOT = Symbol.for('@dudousxd/nestjs-diagnostics:accessor');
const ACME = { id: 'acme', kind: 'organization', source: 'app', role: 'owner' };

/** A structural stand-in for nestjs-context's accessor (with the tenancy methods). */
function context(opts: {
  enabled: boolean;
  filter: TenantFilter;
  tenantId?: string;
  user?: { type: string; id: string | number };
  required?: boolean;
  contextKinds?: string[];
}): TenantContextAccessor & {
  kinds: Array<string[] | undefined>;
  calls: Array<{ kinds?: string[]; family?: string; required?: boolean } | undefined>;
} {
  const kinds: Array<string[] | undefined> = [];
  const calls: Array<{ kinds?: string[]; family?: string; required?: boolean } | undefined> = [];
  return {
    kinds,
    calls,
    tenantId: () => opts.tenantId,
    userRef: () => opts.user,
    tenancy: () => ({
      enabled: opts.enabled,
      ...(opts.required !== undefined ? { required: opts.required } : {}),
      ...(opts.contextKinds ? { kinds: opts.contextKinds } : {}),
    }),
    tenantFilter: (o) => {
      kinds.push(o?.kinds);
      calls.push(o);
      return opts.filter;
    },
  };
}

const resolve = (
  accessor: TenantContextAccessor | undefined,
  extra: Parameters<typeof resolveFull>[1] = {},
) => {
  const { scopes: _scopes, ...rest } = resolveFull(accessor, extra);
  return rest;
};

const resolveFull = (
  accessor: TenantContextAccessor | undefined,
  extra: {
    tenancy?: AuthzTenancyOption;
    resolver?: (user: unknown) => string | null | undefined;
    legacy?: boolean;
    ref?: { type: string; id: number };
  } = {},
) =>
  resolveRbacTenant({
    user: { id: 1 },
    ref: extra.ref ?? { type: 'user', id: 1 },
    accessor,
    tenancy: extra.tenancy,
    resolver: extra.resolver,
    legacyContextTenant: extra.legacy ?? true,
  });

describe("resolveRbacTenant: the core's runInTenantScope (dev tools) wins", () => {
  it('beats the explicit resolver, the context tenant and the legacy tenantId', () => {
    const ctx = context({
      enabled: true,
      filter: { mode: 'tenant', tenant: { ...ACME, id: 'other' } },
      tenantId: 'other',
    });
    const resolver = () => 'resolved';
    expect(runInTenantScope('acme', () => resolve(ctx, { resolver }))).toEqual({
      scope: { tenantId: 'acme' },
      roles: [],
    });
    expect(runInTenantScope(null, () => resolve(ctx, { resolver }))).toEqual({
      scope: {},
      roles: [],
    });
    expect(resolve(ctx, { resolver })).toEqual({ scope: { tenantId: 'resolved' }, roles: [] });
  });

  it('tenancy.roles still maps the caller role when the forced tenant is the context tenant', () => {
    const ctx = context({
      enabled: true,
      filter: { mode: 'tenant', tenant: ACME },
      user: { type: 'user', id: 1 },
    });
    const tenancy = { roles: { owner: 'org_admin' } };
    expect(runInTenantScope('acme', () => resolve(ctx, { tenancy }))).toEqual({
      scope: { tenantId: 'acme' },
      roles: ['org_admin'],
    });
    expect(runInTenantScope('beta', () => resolve(ctx, { tenancy }))).toEqual({
      scope: { tenantId: 'beta' },
      roles: [],
    });
  });
});

const CLINIC = { id: 'c1', kind: 'clinic', role: 'owner' };
const UNIT = { id: 'u1', kind: 'unit', role: 'member' };
const nested = (chainOnFilter: boolean): TenantFilter => ({
  mode: 'tenant',
  tenant: { ...UNIT, source: 'app', chain: [CLINIC, UNIT] },
  ...(chainOnFilter ? { chain: [CLINIC, UNIT] } : {}),
});

describe('resolveRbacTenant: nested tenants (chain)', () => {
  it.each([true, false])(
    'every level of the chain applies, the matched level last (chain on filter: %s)',
    (chainOnFilter) => {
      const ctx = context({ enabled: true, filter: nested(chainOnFilter) });
      expect(resolveFull(ctx)).toEqual({
        scope: { tenantId: 'u1' },
        scopes: [{ tenantId: 'c1' }, { tenantId: 'u1' }],
        roles: [],
      });
    },
  );

  it('kinds limits the levels: only listed ancestors apply', () => {
    const only = context({ enabled: true, filter: nested(true) });
    expect(resolveFull(only, { tenancy: { kinds: ['unit'] } }).scopes).toEqual([
      { tenantId: 'u1' },
    ]);
    expect(only.calls).toEqual([{ kinds: ['unit'] }]);
    const both = context({ enabled: true, filter: nested(true) });
    expect(resolveFull(both, { tenancy: { kinds: ['clinic', 'unit'] } }).scopes).toEqual([
      { tenantId: 'c1' },
      { tenantId: 'u1' },
    ]);
    // The context's kinds count when the module sets none.
    const ctxKinds = context({ enabled: true, filter: nested(true), contextKinds: ['unit'] });
    expect(resolveFull(ctxKinds).scopes).toEqual([{ tenantId: 'u1' }]);
  });

  it('a chain cut at the matched level keeps the levels below out', () => {
    const ctx = context({
      enabled: true,
      filter: { mode: 'tenant', tenant: { ...CLINIC, source: 'app', chain: [CLINIC, UNIT] } },
    });
    expect(resolveFull(ctx).scopes).toEqual([{ tenantId: 'c1' }]);
  });

  it("tenancy.roles maps the caller's role at every level", () => {
    const ctx = context({ enabled: true, filter: nested(true), user: { type: 'user', id: 1 } });
    const tenancy = { roles: { owner: 'clinic_admin', member: 'unit_member' } };
    expect(resolve(ctx, { tenancy })).toEqual({
      scope: { tenantId: 'u1' },
      roles: ['clinic_admin', 'unit_member'],
    });
    // A level the module does not honour maps nothing.
    expect(resolve(ctx, { tenancy: { ...tenancy, kinds: ['unit'] } }).roles).toEqual([
      'unit_member',
    ]);
  });

  it("maps the matched tenant's own role when its chain entry has none", () => {
    const ctx = context({
      enabled: true,
      filter: {
        mode: 'tenant',
        tenant: { ...UNIT, source: 'app' },
        chain: [CLINIC, { id: 'u1', kind: 'unit' }],
      },
      user: { type: 'user', id: 1 },
    });
    expect(resolve(ctx, { tenancy: { roles: { member: 'unit_member' } } }).roles).toEqual([
      'unit_member',
    ]);
  });

  it('passes family through to the context', () => {
    const ctx = context({ enabled: true, filter: { mode: 'tenant', tenant: ACME } });
    resolve(ctx, { tenancy: { family: 'account' } });
    expect(ctx.calls).toEqual([{ family: 'account' }]);
  });
});

describe('resolveRbacTenant: required', () => {
  it('a missing tenant throws when the module or the context requires one', () => {
    const own = context({ enabled: true, filter: { mode: 'tenantless' } });
    expect(() => resolve(own, { tenancy: { required: true } })).toThrow(TenantRequiredError);
    expect(own.calls).toEqual([{ required: true }]);
    const inherited = context({ enabled: true, filter: { mode: 'tenantless' }, required: true });
    expect(() => resolve(inherited)).toThrow(TenantRequiredError);
    // The module can opt out of the context's requirement.
    expect(resolve(inherited, { tenancy: { required: false } })).toEqual({ scope: {}, roles: [] });
  });

  it('the error is a 403 with the context code', () => {
    const ctx = context({ enabled: true, filter: { mode: 'tenantless' } });
    try {
      resolve(ctx, { tenancy: { required: true } });
      expect.unreachable();
    } catch (error) {
      expect((error as TenantRequiredError).getStatus()).toBe(403);
      expect((error as TenantRequiredError).code).toBe('E_TENANT_REQUIRED');
    }
  });

  it('system and all modes, a tenant, and tenancy off never throw', () => {
    for (const filter of [{ mode: 'system' }, { mode: 'all' }] as TenantFilter[]) {
      expect(resolve(context({ enabled: true, filter }), { tenancy: { required: true } })).toEqual({
        scope: {},
        roles: [],
      });
    }
    expect(
      resolve(context({ enabled: false, filter: { mode: 'tenantless' }, required: true })),
    ).toEqual({ scope: {}, roles: [] });
  });

  it('non-request paths and explicit scopes pass required: false', () => {
    const ctx = context({ enabled: true, filter: { mode: 'tenantless' }, required: true });
    expect(runWithoutRequiredTenant(() => resolve(ctx))).toEqual({ scope: {}, roles: [] });
    expect(ctx.calls).toEqual([{ required: false }]);
    expect(resolve(ctx, { resolver: () => 'acme' })).toEqual({
      scope: { tenantId: 'acme' },
      roles: [],
    });
    expect(runInTenantScope('acme', () => resolve(ctx))).toEqual({
      scope: { tenantId: 'acme' },
      roles: [],
    });
  });
});

describe('resolveRbacTenant: tenancy off keeps the adapter behaviour', () => {
  it('no context at all: global scope', () => {
    expect(resolve(undefined)).toEqual({ scope: {}, roles: [] });
  });

  it('an older context (no tenancy methods): the plain tenantId, as before', () => {
    const old = { tenantId: () => 'acme' };
    expect(resolve(old)).toEqual({ scope: { tenantId: 'acme' }, roles: [] });
    expect(resolve(old, { legacy: false })).toEqual({ scope: {}, roles: [] });
  });

  it("context tenancy disabled + 'inherit': the plain tenantId", () => {
    const ctx = context({
      enabled: false,
      filter: { mode: 'tenant', tenant: ACME },
      tenantId: 'x',
    });
    expect(resolve(ctx)).toEqual({ scope: { tenantId: 'x' }, roles: [] });
    expect(ctx.kinds).toEqual([]); // the filter is never asked
  });

  it('tenancy: false opts out even when the context enables it', () => {
    const ctx = context({ enabled: true, filter: { mode: 'tenantless' }, tenantId: 'x' });
    expect(resolve(ctx, { tenancy: false })).toEqual({ scope: { tenantId: 'x' }, roles: [] });
    expect(resolve(ctx, { tenancy: false, legacy: false })).toEqual({ scope: {}, roles: [] });
  });

  it('the tenancy roles map does nothing while tenancy is off', () => {
    const ctx = context({
      enabled: false,
      filter: { mode: 'tenant', tenant: ACME },
      tenantId: 'acme',
      user: { type: 'user', id: 1 },
    });
    expect(resolve(ctx, { tenancy: { roles: { owner: 'org_admin' } } }).roles).toEqual([]);
  });
});

describe('resolveRbacTenant: the matching matrix with tenancy on', () => {
  it.each<[string, TenantFilter, { tenantId?: string }]>([
    ['tenant', { mode: 'tenant', tenant: ACME }, { tenantId: 'acme' }],
    ['tenantless', { mode: 'tenantless' }, {}],
    ['all', { mode: 'all' }, {}],
    ['system', { mode: 'system' }, {}],
  ])('%s mode', (_mode, filter, scope) => {
    // The plain tenantId is ignored once tenancy is on: the filter decides.
    const ctx = context({ enabled: true, filter, tenantId: 'stale' });
    expect(resolve(ctx).scope).toEqual(scope);
    expect(resolve(ctx, { legacy: false }).scope).toEqual(scope);
  });

  it('{ enabled: true } turns it on even when the context switch is off', () => {
    const ctx = context({ enabled: false, filter: { mode: 'tenant', tenant: ACME } });
    expect(resolve(ctx, { tenancy: { enabled: true } }).scope).toEqual({ tenantId: 'acme' });
  });

  it('passes the module kinds to the context filter', () => {
    const ctx = context({ enabled: true, filter: { mode: 'tenantless' } });
    resolve(ctx, { tenancy: { kinds: ['organization'] } });
    resolve(ctx);
    expect(ctx.kinds).toEqual([['organization'], undefined]);
  });

  it('reads the global slot when no accessor was injected', () => {
    const g = globalThis as unknown as Record<symbol, unknown>;
    g[SLOT] = { current: context({ enabled: true, filter: { mode: 'tenant', tenant: ACME } }) };
    try {
      expect(resolve(undefined).scope).toEqual({ tenantId: 'acme' });
    } finally {
      delete g[SLOT];
    }
  });
});

describe('resolveRbacTenant: an explicit tenant resolver wins', () => {
  const ctx = () =>
    context({
      enabled: true,
      filter: { mode: 'tenant', tenant: ACME },
      user: { type: 'user', id: 1 },
    });

  it('a tenant id scopes the check to it', () => {
    expect(resolve(ctx(), { resolver: () => 'globex' }).scope).toEqual({ tenantId: 'globex' });
  });

  it('null is the global scope', () => {
    expect(resolve(ctx(), { resolver: () => null }).scope).toEqual({});
  });

  it('undefined falls back to the context', () => {
    expect(resolve(ctx(), { resolver: () => undefined }).scope).toEqual({ tenantId: 'acme' });
  });

  it('wins with tenancy off too', () => {
    const off = context({ enabled: false, filter: { mode: 'system' }, tenantId: 'acme' });
    expect(resolve(off, { resolver: () => 'globex' }).scope).toEqual({ tenantId: 'globex' });
  });
});

describe('resolveRbacTenant: tenancy.roles', () => {
  const roles = { owner: 'org_admin', member: ['org_member', 'reader'] };
  const ctx = (role: string | undefined, user = { type: 'user', id: 1 }) =>
    context({
      enabled: true,
      filter: {
        mode: 'tenant',
        tenant:
          role === undefined
            ? { id: 'acme', kind: 'organization', source: 'app' }
            : { ...ACME, role },
      },
      user,
    });

  it('maps the caller role inside the tenant (string or list)', () => {
    expect(resolve(ctx('owner'), { tenancy: { roles } }).roles).toEqual(['org_admin']);
    expect(resolve(ctx('member'), { tenancy: { roles } }).roles).toEqual(['org_member', 'reader']);
  });

  it('unmapped roles, no role, or an inherited prototype key grant nothing', () => {
    expect(resolve(ctx('guest'), { tenancy: { roles } }).roles).toEqual([]);
    expect(resolve(ctx(undefined), { tenancy: { roles } }).roles).toEqual([]);
    expect(resolve(ctx('toString'), { tenancy: { roles } }).roles).toEqual([]);
  });

  it('applies only to the context user, not to another user being checked', () => {
    expect(
      resolve(ctx('owner'), { tenancy: { roles }, ref: { type: 'user', id: 2 } }).roles,
    ).toEqual([]);
    expect(resolve(ctx('owner', { type: 'admin', id: 1 }), { tenancy: { roles } }).roles).toEqual(
      [],
    );
  });

  it('applies only in that tenant scope (an explicit resolver elsewhere drops it)', () => {
    expect(resolve(ctx('owner'), { tenancy: { roles }, resolver: () => 'globex' }).roles).toEqual(
      [],
    );
    expect(resolve(ctx('owner'), { tenancy: { roles }, resolver: () => 'acme' }).roles).toEqual([
      'org_admin',
    ]);
  });

  it('applies in tenant mode only', () => {
    const tenantless = context({
      enabled: true,
      filter: { mode: 'tenantless' },
      user: { type: 'user', id: 1 },
    });
    expect(resolve(tenantless, { tenancy: { roles } }).roles).toEqual([]);
  });
});

describe('the tenancy reader is the same file in every adapter', () => {
  const read = (pkg: string) =>
    readFileSync(new URL(`../../${pkg}/src/tenancy.ts`, import.meta.url), 'utf8');

  it.each(['typeorm', 'mikro-orm', 'prisma'])('%s', (pkg) => {
    expect(read(pkg)).toBe(read('drizzle'));
  });
});

afterEach(() => {
  delete (globalThis as unknown as Record<symbol, unknown>)[SLOT];
});
