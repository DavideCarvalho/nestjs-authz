import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type AuthzTenancyOption,
  type TenantContextAccessor,
  type TenantFilter,
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
}): TenantContextAccessor & { kinds: Array<string[] | undefined> } {
  const kinds: Array<string[] | undefined> = [];
  return {
    kinds,
    tenantId: () => opts.tenantId,
    userRef: () => opts.user,
    tenancy: () => ({ enabled: opts.enabled }),
    tenantFilter: (o) => {
      kinds.push(o?.kinds);
      return opts.filter;
    },
  };
}

const resolve = (
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
