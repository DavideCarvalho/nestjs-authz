// Tenancy for the RBAC module: which tenant scope a permission/role check runs in, and which
// roles the caller's role inside the context tenant maps to. The same file ships in every
// store adapter. It reads the @dudousxd/nestjs-context tenancy contract STRUCTURALLY (no import),
// so it works with any context version, and with none: a missing or older context reads as
// tenancy off.
import { CONTEXT_ACCESSOR } from '@dudousxd/nestjs-authz';
import { type UserRef, normalizeUserRef } from '@dudousxd/nestjs-authz/store-kit';
import { ForbiddenException } from '@nestjs/common';
import type { ModuleRef } from '@nestjs/core';

/** One level of a tenant hierarchy (a clinic, a unit inside it), as nestjs-context publishes it. */
export interface TenantLevel {
  id: string;
  kind: string;
  slug?: string;
  role?: string;
}

/** A tenant as published by `@dudousxd/nestjs-context` (`Context.tenant()`). */
export interface TenantRef extends TenantLevel {
  source: string;
  /** The active path when tenants nest, root first and this tenant last. */
  chain?: TenantLevel[];
  family?: string;
}

/** How the context says a lib must scope data right now (`Context.tenantFilter()`). */
export type TenantFilter =
  | { mode: 'system' }
  | { mode: 'all' }
  | { mode: 'tenantless' }
  // `chain` (context >= 2.1): the path down to the matched level, root first.
  | { mode: 'tenant'; tenant: TenantRef; chain?: TenantLevel[] };

/**
 * The RBAC module's `tenancy` option. `'inherit'` (default) follows `ContextModule`'s
 * `tenancy.enabled`; `false` keeps this module out of tenancy.
 */
export type AuthzTenancyOption =
  | 'inherit'
  | false
  | {
      /** `'inherit'` (default) follows the context switch; a boolean overrides it. */
      enabled?: 'inherit' | boolean;
      /**
       * Tenant kinds this module honours, instead of the context's `kinds`. With nested
       * tenants, roles and grants held at every listed level of the active chain apply
       * (e.g. `['clinic', 'unit']`: a clinic role counts inside its units).
       */
      kinds?: string[];
      /** Only the tenant of this family counts (a request can carry several). */
      family?: string;
      /**
       * A check with no tenant throws `TenantRequiredError` (403, `E_TENANT_REQUIRED`) instead
       * of running in the global scope. Default: the context's `tenancy.required`. Console
       * access checks and dev tools never require one.
       */
      required?: boolean;
      /**
       * Accepted for the shared shape. It changes nothing here: a GLOBAL role assignment
       * always applies, in every tenant.
       */
      nullRows?: 'tenantless' | 'shared';
      /**
       * Map the caller's role inside the context tenant (`tenant.role`) to authz roles that
       * apply in that tenant's scope only, e.g. `{ owner: 'org_admin', member: 'org_member' }`.
       * With nested tenants, the caller's role at each level of the chain is mapped.
       * Unmapped roles grant nothing.
       */
      roles?: Record<string, string | readonly string[]>;
    };

/**
 * An explicit tenant for a check, from the user being checked. Return a tenant id to scope the
 * check to it, `null` for the global scope, or `undefined` to fall back to the context.
 */
export type TenantResolver = (user: unknown) => string | null | undefined;

/** The structural slice of nestjs-context's accessor this module reads. */
export interface TenantContextAccessor {
  tenantId?(): string | undefined;
  userRef?(): { type?: string; id: string | number } | undefined;
  tenancy?(): { enabled: boolean; kinds?: string[]; required?: boolean };
  tenantFilter?(options?: { kinds?: string[]; family?: string; required?: boolean }): TenantFilter;
}

const SLOT = Symbol.for('@dudousxd/nestjs-diagnostics:accessor');

/** The core's `runInTenantScope` storage, read structurally (any core version, or none). */
const TENANT_SCOPE_SLOT = Symbol.for('@dudousxd/nestjs-authz:tenant-scope');

/** What the core's `runInTenantScope` / `runWithoutRequiredTenant` force here, if anything. */
function forced(): { scope?: { tenantId: string | null }; relaxed: boolean } {
  const slot = (globalThis as unknown as Record<symbol, unknown>)[TENANT_SCOPE_SLOT] as
    | { storage?: { getStore?(): unknown } }
    | undefined;
  const store = slot?.storage?.getStore?.() as
    | { tenantId?: unknown; required?: unknown }
    | undefined;
  if (!store) return { relaxed: false };
  const relaxed = store.required === false;
  const id = store.tenantId;
  return id === null || typeof id === 'string' ? { scope: { tenantId: id }, relaxed } : { relaxed };
}

/** The error `required` raises, shaped like nestjs-context's `TenantRequiredError`. */
export class TenantRequiredError extends ForbiddenException {
  readonly code = 'E_TENANT_REQUIRED';
  constructor() {
    super({
      statusCode: 403,
      error: 'Forbidden',
      code: 'E_TENANT_REQUIRED',
      message: 'This action needs an active tenant (organization). Select one and retry.',
    });
    this.name = 'TenantRequiredError';
  }
}

type Tenancy =
  | { enabled: false }
  | { enabled: true; kinds: string[] | undefined; filter(): TenantFilter };

/** Is tenancy on for this module? Call per check: the context can change between requests. */
function readTenancy(
  option: AuthzTenancyOption | undefined,
  a: TenantContextAccessor | undefined,
  relaxed: boolean,
): Tenancy {
  if (option === false) return { enabled: false };
  if (typeof a?.tenancy !== 'function' || typeof a.tenantFilter !== 'function') {
    return { enabled: false };
  }
  const own = typeof option === 'object' ? option : {};
  const inherit = own.enabled === undefined || own.enabled === 'inherit';
  const context = a.tenancy();
  if (!(inherit ? context.enabled : own.enabled)) return { enabled: false };
  const options: { kinds?: string[]; family?: string; required?: boolean } = {};
  if (own.kinds) options.kinds = own.kinds;
  if (own.family !== undefined) options.family = own.family;
  const required = relaxed ? false : (own.required ?? context.required === true);
  if (relaxed) options.required = false;
  else if (own.required !== undefined) options.required = own.required;
  const tenantFilter = a.tenantFilter.bind(a);
  return {
    enabled: true,
    kinds: own.kinds ?? context.kinds,
    filter: () => {
      // A context that knows `required` throws its own TenantRequiredError here.
      const filter = tenantFilter(Object.keys(options).length > 0 ? options : undefined);
      // An older one answers `tenantless`: raise the same error.
      if (required && filter.mode === 'tenantless') throw new TenantRequiredError();
      return filter;
    },
  };
}

/** The levels of a `tenant` filter that scope this module, root first, the matched level last. */
function scopeLevels(
  filter: Extract<TenantFilter, { mode: 'tenant' }>,
  kinds: string[] | undefined,
): TenantLevel[] {
  const path =
    filter.chain && filter.chain.length > 0
      ? filter.chain
      : filter.tenant.chain && filter.tenant.chain.length > 0
        ? cutAt(filter.tenant.chain, filter.tenant)
        : [filter.tenant];
  const last = path[path.length - 1];
  return path.filter((level) => level === last || !kinds || kinds.includes(level.kind));
}

/** `chain` up to and including `tenant` (the whole chain when it is not in it). */
function cutAt(chain: TenantLevel[], tenant: TenantLevel): TenantLevel[] {
  const at = chain.findIndex((level) => level.id === tenant.id && level.kind === tenant.kind);
  return at === -1 ? [...chain, tenant] : chain.slice(0, at + 1);
}

/** The accessor found through DI, else the global slot `ContextModule` publishes. */
function effectiveAccessor(
  injected: TenantContextAccessor | undefined,
): TenantContextAccessor | undefined {
  if (injected) return injected;
  const slot = (globalThis as unknown as Record<symbol, { current?: unknown } | undefined>)[SLOT];
  const current = slot?.current;
  return current && typeof current === 'object' ? (current as TenantContextAccessor) : undefined;
}

/** Today's behaviour without tenancy: the context's plain `tenantId()`, read defensively. */
function legacyTenantId(accessor: TenantContextAccessor | undefined): string | undefined {
  if (!accessor || typeof accessor.tenantId !== 'function') return undefined;
  try {
    return accessor.tenantId() ?? undefined;
  } catch {
    return undefined;
  }
}

/** Is `ref` the context's current user? Tenant roles belong to the caller, nobody else. */
function isContextUser(ref: UserRef, accessor: TenantContextAccessor | undefined): boolean {
  let current: { type?: string; id: string | number } | undefined;
  try {
    current = accessor?.userRef?.();
  } catch {
    current = undefined;
  }
  if (!current || current.id === undefined || current.id === null) return false;
  const a = normalizeUserRef(ref);
  const b = normalizeUserRef(current);
  return a.type === b.type && a.id === b.id;
}

/** The tenant scope of one check, plus the roles `tenancy.roles` adds in that scope. */
export interface RbacTenant {
  /** The most specific scope (the matched tenant), or `{}` for the global scope. */
  scope: { tenantId?: string };
  /**
   * Every scope whose roles and grants apply, root first: the levels of a nested tenant the
   * module honours, or just `scope`.
   */
  scopes: Array<{ tenantId?: string }>;
  roles: string[];
}

export interface ResolveRbacTenantInput {
  /** The user as the Gate passed it. */
  user: unknown;
  /** The same user mapped to a store ref. */
  ref: UserRef;
  /** The module's explicit `tenant` resolver, if any. */
  resolver?: TenantResolver | undefined;
  /** The module's `tenancy` option. */
  tenancy?: AuthzTenancyOption | undefined;
  /** The context accessor found through DI, if any (else the global slot is read). */
  accessor?: TenantContextAccessor | undefined;
  /** With tenancy off, scope by the context's plain `tenantId()` (drizzle/typeorm behaviour). */
  legacyContextTenant: boolean;
}

/**
 * Precedence: a scope forced by the core's `runInTenantScope` (the dev tools), then the
 * explicit `tenant` resolver, then (tenancy on) the context tenant filter, then (tenancy off)
 * the adapter's behaviour without tenancy. `tenant` mode scopes to that tenant and, for a nested
 * tenant, to each level above it the module honours; `tenantless`, `all` and `system` use the
 * global scope. With `required`, `tenantless` throws {@link TenantRequiredError}.
 */
export function resolveRbacTenant(input: ResolveRbacTenantInput): RbacTenant {
  const force = forced();
  const explicit = force.scope
    ? force.scope.tenantId
    : input.resolver
      ? input.resolver(input.user)
      : undefined;
  const accessor = effectiveAccessor(input.accessor);
  // An explicit scope never needs a tenant from the context.
  const tenancy = readTenancy(input.tenancy, accessor, force.relaxed || explicit !== undefined);
  const filter = tenancy.enabled ? tenancy.filter() : undefined;
  const own = typeof input.tenancy === 'object' ? input.tenancy : {};
  const levels =
    tenancy.enabled && filter?.mode === 'tenant' ? scopeLevels(filter, tenancy.kinds) : [];

  let scopes: Array<{ tenantId?: string }>;
  if (explicit !== undefined) {
    scopes = [explicit === null ? {} : { tenantId: explicit }];
  } else if (filter) {
    scopes = levels.length > 0 ? levels.map((level) => ({ tenantId: level.id })) : [{}];
  } else if (input.legacyContextTenant) {
    const id = legacyTenantId(input.accessor);
    scopes = [id === undefined ? {} : { tenantId: id }];
  } else {
    scopes = [{}];
  }
  const scope = scopes[scopes.length - 1] ?? {};

  // The caller's role at each level in scope, mapped by `tenancy.roles`.
  const map = own.roles;
  const roles = new Set<string>();
  if (map && levels.length > 0 && isContextUser(input.ref, accessor)) {
    const inScope = new Set(scopes.map((s) => s.tenantId));
    const matched = filter?.mode === 'tenant' ? filter.tenant : undefined;
    for (const level of levels) {
      // The matched level's role may live only on the tenant itself, not on its chain entry.
      const role =
        level.role ??
        (matched && level.id === matched.id && level.kind === matched.kind
          ? matched.role
          : undefined);
      if (role === undefined || !inScope.has(level.id)) continue;
      if (!Object.prototype.hasOwnProperty.call(map, role)) continue;
      const mapped = map[role];
      for (const role of typeof mapped === 'string' ? [mapped] : (mapped ?? [])) roles.add(role);
    }
  }
  return { scope, scopes, roles: [...roles] };
}

/**
 * Run `read` once per scope of `tenant` and merge the results (one call for a flat tenant).
 */
export async function acrossScopes<T>(
  tenant: RbacTenant,
  read: (scope: { tenantId?: string }) => Promise<readonly T[]>,
): Promise<T[]> {
  if (tenant.scopes.length <= 1) return [...(await read(tenant.scope))];
  const all = await Promise.all(tenant.scopes.map(read));
  return [...new Set(all.flat())];
}

/** True when `test` holds in any scope of `tenant`. */
export async function inAnyScope(
  tenant: RbacTenant,
  test: (scope: { tenantId?: string }) => Promise<boolean>,
): Promise<boolean> {
  for (const scope of tenant.scopes) if (await test(scope)) return true;
  return false;
}

/**
 * Locate the context accessor. Prefers a value injected into the module; falls back to a
 * non-strict {@link ModuleRef} lookup so an accessor provided by ANY module (the app root, a
 * global ContextModule) is still found: the RBAC module is global and its providers don't import
 * the app's modules, so a plain `@Inject` would miss a root-provided accessor.
 */
function resolveTenantContext(
  injected: TenantContextAccessor | undefined,
  moduleRef: ModuleRef | undefined,
  cache: { resolved: boolean; value: TenantContextAccessor | undefined },
): TenantContextAccessor | undefined {
  if (injected) return injected;
  if (cache.resolved) return cache.value;
  cache.resolved = true;
  if (moduleRef) {
    try {
      cache.value = moduleRef.get<TenantContextAccessor>(CONTEXT_ACCESSOR, { strict: false });
    } catch {
      cache.value = undefined;
    }
  }
  return cache.value;
}

/** A provider's per-instance cache for {@link rbacTenant}'s accessor lookup. */
export interface TenantContextCache {
  resolved: boolean;
  value: TenantContextAccessor | undefined;
}

/** The tenant scope (and `tenancy.roles` roles) of one check for `user`. */
export function rbacTenant(
  options: { tenant?: TenantResolver | undefined; tenancy?: AuthzTenancyOption | undefined },
  user: unknown,
  ref: UserRef,
  injected: TenantContextAccessor | undefined,
  moduleRef: ModuleRef | undefined,
  cache: TenantContextCache,
  legacyContextTenant: boolean,
): RbacTenant {
  return resolveRbacTenant({
    user,
    ref,
    resolver: options.tenant,
    tenancy: options.tenancy,
    accessor: resolveTenantContext(injected, moduleRef, cache),
    legacyContextTenant,
  });
}
