import 'reflect-metadata';
import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import { Policy } from '@nestjs/authorization';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthzConsoleGate } from '../src/console.js';
import { type AuthzDevTool, DEV_TOOLS_SLOT } from '../src/dev-tools.js';
import { authzDecisionChannel } from '../src/diagnostics.js';
import { Gate } from '../src/gate.js';
import { PolicyFor } from '../src/links.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import type { RbacDescription, RoleProvider } from '../src/role-provider.js';
import { currentTenantScopeOverride } from '../src/tenant-override.js';
import { DECISION_PROVIDER } from '../src/tokens.js';
import { type BootOptions, bootContext, permissionTable } from './support/app.js';

interface SlotLib {
  lib: string;
  title: string;
  authorize?: unknown;
  tools: AuthzDevTool[];
}

type Slot = { version: number; libs: SlotLib[]; supports?: (c: string) => boolean };

function slot(): Slot | undefined {
  return (globalThis as Record<symbol, never>)[DEV_TOOLS_SLOT];
}

function tool(name: string): AuthzDevTool {
  const found = slot()
    ?.libs.find((l) => l.lib === 'authz')
    ?.tools.find((t) => t.name === name);
  if (!found) throw new Error(`no tool ${name}`);
  return found;
}

class Post {
  constructor(
    readonly id: string,
    readonly ownerId: string,
  ) {}
}

@Policy()
@PolicyFor(Post)
class PostPolicy {
  update(user: { id: string } | null, post: Post) {
    return user?.id === post.ownerId;
  }
}

/**
 * A role provider shaped like the RBAC adapters': store roles per tenant, a `describeRbac`, and
 * the forced scope of `runInTenantScope` read like the adapters read it.
 */
function rbacProvider(): RoleProvider & { scopes: Array<string | null> } {
  const assigned: Record<string, Record<string, string[]>> = {
    '': { '1': ['viewer'] },
    acme: { '1': ['editor'] },
  };
  const rolePermissions: Record<string, string[]> = {
    viewer: ['posts.view'],
    editor: ['posts.*'],
  };
  const direct: Record<string, string[]> = { '1': ['posts.update', 'reports.view'] };
  const scopes: Array<string | null> = [];
  const scope = () => currentTenantScopeOverride()?.tenantId ?? null;
  const rolesOf = (id: string, tenant: string | null) => [
    ...(assigned['']?.[id] ?? []),
    ...(tenant ? (assigned[tenant]?.[id] ?? []) : []),
  ];
  return {
    scopes,
    getRoles: (user) => rolesOf(String((user as { id: unknown }).id), scope()),
    async describeRbac(user): Promise<RbacDescription> {
      const id = String((user as { id: unknown }).id);
      const tenantId = scope();
      scopes.push(tenantId);
      const roles = rolesOf(id, tenantId);
      return {
        tenantId,
        roles: { store: roles, tenant: [] },
        rolePermissions: Object.fromEntries(roles.map((r) => [r, rolePermissions[r] ?? []])),
        permissions: [
          ...new Set([...roles.flatMap((r) => rolePermissions[r] ?? []), ...(direct[id] ?? [])]),
        ],
      };
    },
  };
}

/** A permission provider that reads the same fake store as {@link rbacProvider}. */
function permissionsOf(roles: ReturnType<typeof rbacProvider>): PermissionProvider {
  const list = async (user: unknown) => (await roles.describeRbac?.(user))?.permissions ?? [];
  return {
    hasPermission: async (user, permission) => (await list(user)).includes(permission),
    getPermissions: list,
  };
}

describe('authz dev tools', () => {
  beforeEach(() => {
    delete (globalThis as Record<symbol, unknown>)[DEV_TOOLS_SLOT];
  });
  afterEach(() => {
    delete (globalThis as Record<symbol, unknown>)[DEV_TOOLS_SLOT];
  });

  async function boot(options: BootOptions = {}) {
    const { mod } = await bootContext(options);
    return mod;
  }

  it('creates the slot, registers without authorize, and removes itself on close', async () => {
    const mod = await boot();
    const lib = slot()?.libs.find((l) => l.lib === 'authz');
    expect(lib).toBeDefined();
    expect(lib?.authorize).toBeUndefined();
    expect(lib?.tools.map((t) => t.name)).toEqual([
      'authz_explain_check',
      'authz_list_effective_roles',
      'authz_list_effective_permissions',
    ]);
    expect(lib?.tools.every((t) => t.kind === 'read')).toBe(true);
    await mod.close();
    expect(slot()?.libs.find((l) => l.lib === 'authz')).toBeUndefined();
  });

  it('registers into a hub that supports endpoint-authorize', async () => {
    const libs: SlotLib[] = [];
    (globalThis as Record<symbol, unknown>)[DEV_TOOLS_SLOT] = {
      version: 1,
      libs,
      register: (lib: SlotLib) => {
        libs.push(lib);
        return () => libs.splice(libs.indexOf(lib), 1);
      },
      supports: (c: string) => c === 'endpoint-authorize',
    };
    const mod = await boot();
    expect(libs.map((l) => l.lib)).toEqual(['authz']);
    await mod.close();
    expect(libs).toEqual([]);
  });

  it('stays out of a hub that cannot gate a lib without a console', async () => {
    const register = vi.fn();
    (globalThis as Record<symbol, unknown>)[DEV_TOOLS_SLOT] = {
      version: 1,
      libs: [],
      register,
      supports: () => false,
    };
    const mod = await boot();
    expect(register).not.toHaveBeenCalled();
    await mod.close();
  });

  it('devTools: false leaves them out', async () => {
    const mod = await boot({ authz: { devTools: false } });
    expect(slot()?.libs.find((l) => l.lib === 'authz')).toBeUndefined();
    await mod.close();
  });

  it('explains a permission granted by a store role and a direct grant, per tenant', async () => {
    const roles = rbacProvider();
    const mod = await boot({ roles, permissions: permissionsOf(roles) });
    const explain = tool('authz_explain_check');

    const global = (await explain.run({ subjectId: '1', permission: 'posts.update' })) as Record<
      string,
      unknown
    >;
    expect(global).toMatchObject({
      allowed: true,
      reason: 'permission-provider',
      subject: { type: 'user', id: '1' },
      tenant: { id: null, from: 'global' },
      effectiveRoles: ['viewer'],
      roleSources: { viewer: ['store'] },
      grantingRoles: [],
      directGrants: ['posts.update'],
      superAdmin: false,
      decisionProvider: 'none',
      subjectLoaded: false,
    });

    const acme = (await explain.run({
      subjectId: '1',
      permission: 'posts.view',
      tenantId: 'acme',
    })) as Record<string, unknown>;
    expect(acme).toMatchObject({
      allowed: true,
      reason: 'permission-provider',
      tenant: { id: 'acme', from: 'explicit' },
      effectiveRoles: ['viewer', 'editor'],
      grantingRoles: [
        { role: 'viewer', matched: ['posts.view'] },
        { role: 'editor', matched: ['posts.*'] },
      ],
      directGrants: [],
    });
    // The Gate's grant check, describeRbac and the coverage list: each in the requested scope.
    expect(roles.scopes).toEqual([null, null, null, 'acme', 'acme', 'acme']);
    await mod.close();
  });

  it('coverage only counts what the permission provider lists', async () => {
    const roles = rbacProvider();
    const { provider } = permissionTable({ '1': ['posts.view'] });
    const mod = await boot({ roles, permissions: provider });
    const result = await tool('authz_explain_check').run({
      subjectId: '1',
      permission: 'posts.update',
      tenantId: 'acme',
    });
    // The store says editor has posts.* and a direct posts.update, but the deciding provider
    // grants neither: the answer does not claim them.
    expect(result).toMatchObject({
      allowed: false,
      reason: 'unresolved',
      grantingRoles: [],
      directGrants: [],
    });
    await mod.close();
  });

  it('loaders run inside the requested tenant', async () => {
    const seen: Array<unknown> = [];
    const mod = await boot({
      authz: {
        devTools: {
          loadSubject: (ref) => {
            seen.push(currentTenantScopeOverride()?.tenantId);
            return { id: ref.id };
          },
          loadResource: (ref) => {
            seen.push(currentTenantScopeOverride()?.tenantId);
            return { id: ref.id };
          },
        },
      },
    });
    await tool('authz_explain_check').run({
      subjectId: '1',
      permission: 'x',
      tenantId: 'acme',
      resourceType: 'Post',
      resourceId: '1',
    });
    await tool('authz_list_effective_roles').run({ subjectId: '1', tenantId: 'beta' });
    await tool('authz_list_effective_permissions').run({ subjectId: '1', tenantId: '' });
    expect(seen).toEqual(['acme', 'acme', 'beta', null]);
    await mod.close();
  });

  it('a numeric tenantId is a tenant; another type is an error', async () => {
    const roles = rbacProvider();
    const mod = await boot({ roles });
    const result = await tool('authz_list_effective_roles').run({ subjectId: '1', tenantId: 42 });
    expect(result).toMatchObject({ tenant: { id: '42', from: 'explicit' } });
    await expect(
      tool('authz_list_effective_roles').run({ subjectId: '1', tenantId: true }),
    ).rejects.toThrow('`tenantId` must be a string');
    await mod.close();
  });

  it("'' forces the global scope", async () => {
    const roles = rbacProvider();
    const mod = await boot({ roles });
    await tool('authz_list_effective_roles').run({ subjectId: '1', tenantId: '' });
    expect(roles.scopes).toEqual([null]);
    expect(currentTenantScopeOverride()).toBeUndefined();
    await mod.close();
  });

  it('reports super-admin and a decision provider that was not consulted', async () => {
    const decide = vi.fn(() => false);
    const mod = await boot({
      authz: { superAdmin: (user) => (user as { id: string }).id === '9' },
      providers: [{ provide: DECISION_PROVIDER, useValue: { decide } }],
    });
    const result = await tool('authz_explain_check').run({ subjectId: '9', permission: 'x' });
    expect(result).toMatchObject({
      allowed: true,
      reason: 'super-admin',
      superAdmin: true,
      decisionProvider: 'not-consulted',
    });
    expect(decide).not.toHaveBeenCalled();
    await mod.close();
  });

  it('reports the decision provider verdict and its message', async () => {
    const mod = await boot({
      providers: [
        {
          provide: DECISION_PROVIDER,
          useValue: { decide: () => ({ allowed: false, message: 'outside business hours' }) },
        },
      ],
    });
    const result = await tool('authz_explain_check').run({ subjectId: '1', permission: 'x' });
    expect(result).toMatchObject({
      allowed: false,
      reason: 'decision-provider',
      decisionProvider: 'denied',
      message: 'outside business hours',
    });
    await mod.close();
  });

  it('loadSubject and loadResource hand the policy real models', async () => {
    const loadSubject = vi.fn((ref: { id: string }) => ({ id: ref.id, name: 'Alice' }));
    const loadResource = vi.fn((ref: { type: string; id: string }) =>
      ref.type === 'Post' ? new Post(ref.id, '1') : undefined,
    );
    const mod = await boot({
      providers: [PostPolicy],
      authz: { devTools: { loadSubject, loadResource } },
    });
    const explain = tool('authz_explain_check');
    const own = await explain.run({
      subjectId: '1',
      permission: 'update',
      resourceType: 'Post',
      resourceId: '7',
    });
    expect(own).toMatchObject({
      allowed: true,
      reason: 'policy',
      policy: 'PostPolicy',
      subjectLoaded: true,
      resource: { type: 'Post', id: '7' },
      resourceLoaded: true,
    });
    const other = await explain.run({
      subjectId: '2',
      permission: 'update',
      resourceType: 'Post',
      resourceId: '7',
    });
    expect(other).toMatchObject({ allowed: false, reason: 'policy' });
    expect(loadSubject).toHaveBeenCalledWith({ type: 'user', id: '1' });
    await mod.close();
  });

  it('falls back to resolveUser and resourceLoaders', async () => {
    const mod = await boot({
      providers: [PostPolicy],
      authz: {
        resolveUser: (ref) => ({ id: String(ref.id) }),
        resourceLoaders: { Post: (id) => new Post(String(id), '1') },
      },
    });
    const result = await tool('authz_explain_check').run({
      subjectId: '1',
      permission: 'update',
      resourceType: 'Post',
      resourceId: '3',
    });
    expect(result).toMatchObject({ allowed: true, subjectLoaded: true, resourceLoaded: true });
    await mod.close();
  });

  it('publishes no decision event', async () => {
    const seen = vi.fn();
    subscribe(authzDecisionChannel.name, seen);
    try {
      const { provider } = permissionTable({ '1': ['posts.view'] });
      const mod = await boot({ permissions: provider });
      await tool('authz_explain_check').run({ subjectId: '1', permission: 'posts.view' });
      expect(seen).not.toHaveBeenCalled();
      await mod.close();
    } finally {
      unsubscribe(authzDecisionChannel.name, seen);
    }
  });

  it('validates its input', async () => {
    const mod = await boot();
    const explain = tool('authz_explain_check');
    await expect(explain.run({ permission: 'x' })).rejects.toThrow('`subjectId` is required');
    await expect(explain.run({ subjectId: '1' })).rejects.toThrow('`permission` is required');
    await expect(
      explain.run({ subjectId: '1', permission: 'x', resourceType: 'Post' }),
    ).rejects.toThrow('go together');
    await mod.close();
  });

  it('lists effective roles with sources, and pages effective permissions', async () => {
    const roles = rbacProvider();
    const { provider } = permissionTable({ '1': ['b', 'a', 'c'] });
    const mod = await boot({
      roles,
      permissions: provider,
      authz: { resolveRoles: () => ['viewer', 'staff'] },
    });
    const listed = await tool('authz_list_effective_roles').run({
      subjectId: '1',
      tenantId: 'acme',
    });
    expect(listed).toMatchObject({
      items: [
        { role: 'viewer', sources: ['user', 'store'] },
        { role: 'staff', sources: ['user'] },
        { role: 'editor', sources: ['store'] },
      ],
      next: null,
    });
    const first = await tool('authz_list_effective_permissions').run({ subjectId: '1', limit: 2 });
    expect(first).toMatchObject({ items: ['a', 'b'], next: 2 });
    const second = await tool('authz_list_effective_permissions').run({
      subjectId: '1',
      limit: 2,
      page: 2,
    });
    expect(second).toMatchObject({ items: ['c'], next: null });
    await mod.close();
  });

  it('warns when the role provider cannot take a tenant', async () => {
    const mod = await boot({ roles: { getRoles: () => ['viewer'] } });
    const result = await tool('authz_list_effective_roles').run({
      subjectId: '1',
      tenantId: 'acme',
    });
    expect(result).toMatchObject({
      items: [{ role: 'viewer', sources: ['provider'] }],
      warning: expect.stringContaining('cannot take `tenantId`'),
    });
    await mod.close();
  });
});

describe('tenancy.required outside tenant-scoped requests', () => {
  it('console access checks and dev tools run with required: false', async () => {
    const seen: Array<unknown> = [];
    const roles: RoleProvider = {
      getRoles: () => {
        seen.push(currentTenantScopeOverride()?.required);
        return ['admin'];
      },
    };
    const { mod } = await bootContext({ roles });
    const consoleGate = mod.get(AuthzConsoleGate);
    const context = {
      switchToHttp: () => ({ getRequest: () => ({ headers: { 'x-user': '{"id":"1"}' } }) }),
      getType: () => 'http',
    } as never;
    expect(
      await consoleGate.check(context, (user) => mod.get(Gate).forUser(user).hasRole('admin')),
    ).toBe(true);
    await tool('authz_list_effective_roles').run({ subjectId: '1' });
    expect(seen).toEqual([false, false]);
    expect(currentTenantScopeOverride()).toBeUndefined();
    await mod.close();
  });
});
