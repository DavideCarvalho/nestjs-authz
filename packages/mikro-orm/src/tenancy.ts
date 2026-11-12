// Tenancy for the RBAC module: which tenant scope a permission/role check runs in, and which
// roles the caller's role inside the context tenant maps to. The same file ships in every
// store adapter. It reads the @dudousxd/nestjs-context tenancy contract STRUCTURALLY (no import),
// so it works with any context version, and with none: a missing or older context reads as
// tenancy off.
import { CONTEXT_ACCESSOR } from '@dudousxd/nestjs-authz';
import { type UserRef, normalizeUserRef } from '@dudousxd/nestjs-authz/store-kit';
import type { ModuleRef } from '@nestjs/core';

/** A tenant as published by `@dudousxd/nestjs-context` (`Context.tenant()`). */
export interface TenantRef {
  id: string;
  kind: string;
  source: string;
  slug?: string;
  role?: string;
}

/** How the context says a lib must scope data right now (`Context.tenantFilter()`). */
export type TenantFilter =
  | { mode: 'system' }
  | { mode: 'all' }
  | { mode: 'tenantless' }
  | { mode: 'tenant'; tenant: TenantRef };

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
      /** Tenant kinds this module honours, instead of the context's `kinds`. */
      kinds?: string[];
      /**
       * Accepted for the shared shape. It changes nothing here: a GLOBAL role assignment
       * always applies, in every tenant.
       */
      nullRows?: 'tenantless' | 'shared';
      /**
       * Map the caller's role inside the context tenant (`tenant.role`) to authz roles that
       * apply in that tenant's scope only, e.g. `{ owner: 'org_admin', member: 'org_member' }`.
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
  tenancy?(): { enabled: boolean; kinds?: string[] };
  tenantFilter?(options?: { kinds?: string[] }): TenantFilter;
}

const SLOT = Symbol.for('@dudousxd/nestjs-diagnostics:accessor');

type Tenancy = { enabled: false } | { enabled: true; filter(): TenantFilter };

/** Is tenancy on for this module? Call per check: the context can change between requests. */
function readTenancy(
  option: AuthzTenancyOption | undefined,
  a: TenantContextAccessor | undefined,
): Tenancy {
  if (option === false) return { enabled: false };
  if (typeof a?.tenancy !== 'function' || typeof a.tenantFilter !== 'function') {
    return { enabled: false };
  }
  const own = typeof option === 'object' ? option : {};
  const inherit = own.enabled === undefined || own.enabled === 'inherit';
  if (!(inherit ? a.tenancy().enabled : own.enabled)) return { enabled: false };
  const kinds = own.kinds;
  const tenantFilter = a.tenantFilter.bind(a);
  return { enabled: true, filter: () => tenantFilter(kinds ? { kinds } : undefined) };
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
  scope: { tenantId?: string };
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
 * Precedence: the explicit `tenant` resolver, then (tenancy on) the context tenant filter, then
 * (tenancy off) the adapter's behaviour without tenancy. `tenant` mode scopes to that tenant;
 * `tenantless`, `all` and `system` use the global scope.
 */
export function resolveRbacTenant(input: ResolveRbacTenantInput): RbacTenant {
  const explicit = input.resolver ? input.resolver(input.user) : undefined;
  const accessor = effectiveAccessor(input.accessor);
  const tenancy = readTenancy(input.tenancy, accessor);
  const filter = tenancy.enabled ? tenancy.filter() : undefined;

  let scope: { tenantId?: string };
  if (explicit !== undefined) {
    scope = explicit === null ? {} : { tenantId: explicit };
  } else if (filter) {
    scope = filter.mode === 'tenant' ? { tenantId: filter.tenant.id } : {};
  } else if (input.legacyContextTenant) {
    const id = legacyTenantId(input.accessor);
    scope = id === undefined ? {} : { tenantId: id };
  } else {
    scope = {};
  }

  const map = typeof input.tenancy === 'object' ? input.tenancy.roles : undefined;
  let roles: string[] = [];
  if (
    map &&
    filter?.mode === 'tenant' &&
    filter.tenant.role !== undefined &&
    scope.tenantId === filter.tenant.id &&
    Object.prototype.hasOwnProperty.call(map, filter.tenant.role) &&
    isContextUser(input.ref, accessor)
  ) {
    const mapped = map[filter.tenant.role];
    roles = typeof mapped === 'string' ? [mapped] : [...(mapped ?? [])];
  }
  return { scope, roles };
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
