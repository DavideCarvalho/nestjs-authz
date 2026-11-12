import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * An explicit tenant scope for every RBAC lookup made inside {@link runInTenantScope}: what the
 * `authz_explain_check` dev tool uses to ask "in tenant T" without a request in that tenant.
 *
 * The storage lives in a process-wide slot so the store adapters read it STRUCTURALLY
 * (`globalThis[Symbol.for('@dudousxd/nestjs-authz:tenant-scope')].storage.getStore()`) without
 * importing this package's newer exports. An adapter that predates it ignores the override.
 */
export const TENANT_SCOPE_SLOT = Symbol.for('@dudousxd/nestjs-authz:tenant-scope');

/**
 * What the current call forces: `tenantId` (a tenant id, or `null` for the global scope), and
 * `required: false` to never throw for a missing tenant (`tenancy.required`).
 */
export interface TenantScopeOverride {
  tenantId?: string | null;
  required?: false;
}

interface TenantScopeSlot {
  readonly version: 1;
  readonly storage: AsyncLocalStorage<TenantScopeOverride>;
}

function slot(): TenantScopeSlot {
  const holder = globalThis as Record<symbol, unknown>;
  const existing = holder[TENANT_SCOPE_SLOT] as TenantScopeSlot | undefined;
  if (existing?.version === 1 && existing.storage instanceof AsyncLocalStorage) return existing;
  const created: TenantScopeSlot = { version: 1, storage: new AsyncLocalStorage() };
  holder[TENANT_SCOPE_SLOT] = created;
  return created;
}

/**
 * Run `fn` with every RBAC role/permission lookup scoped to `tenantId` (`null` = the global
 * scope), ahead of the adapter's `tenant` resolver and the context tenant.
 */
export function runInTenantScope<T>(tenantId: string | null, fn: () => T): T {
  const storage = slot().storage;
  return storage.run({ ...storage.getStore(), tenantId }, fn);
}

/**
 * Run `fn` where a missing tenant is not an error, even with `tenancy.required`: for paths that
 * are not tenant-scoped requests (console access checks, dev tools, jobs). Checks with no tenant
 * use the global scope there.
 */
export function runWithoutRequiredTenant<T>(fn: () => T): T {
  const storage = slot().storage;
  return storage.run({ ...storage.getStore(), required: false }, fn);
}

/** What the current call forces, or `undefined` outside {@link runInTenantScope} / {@link runWithoutRequiredTenant}. */
export function currentTenantScopeOverride(): TenantScopeOverride | undefined {
  const existing = (globalThis as Record<symbol, unknown>)[TENANT_SCOPE_SLOT] as
    | TenantScopeSlot
    | undefined;
  return existing?.storage?.getStore();
}
