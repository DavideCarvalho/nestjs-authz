import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import type { ContextAccessor, ContextStore, UserRef } from '../src/context-accessor.js';
import { Gate } from '../src/gate.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PolicyRegistry } from '../src/policy-registry.js';

/**
 * A context accessor backed by a single mutable store object — mirrors how
 * nestjs-context exposes a per-request store via `get()`. The Gate stashes its
 * per-request permission cache on this store, so two checks within the same
 * request share one fetch.
 */
function contextWithStore(ref: UserRef | undefined): {
  accessor: ContextAccessor;
  store: ContextStore;
} {
  const store: ContextStore = {};
  const accessor: ContextAccessor = {
    traceId: () => undefined,
    tenantId: () => undefined,
    userRef: () => ref,
    get: () => store,
  };
  return { accessor, store };
}

describe('request-scoped permission cache (N+1 avoidance)', () => {
  it('fetches permissions ONCE across multiple allows() in one request (context store)', async () => {
    const getPermissions = vi.fn(() => ['posts.*']);
    const provider: PermissionProvider = { hasPermission: () => false, getPermissions };
    const { accessor } = contextWithStore({ type: 'user', id: 5 });
    const gate = new Gate(new PolicyRegistry(), {}, accessor, undefined, provider);

    // Three separate allows() calls within the SAME request (same context store).
    expect(await gate.allows('posts.update')).toBe(true);
    expect(await gate.allows('posts.delete')).toBe(true);
    expect(await gate.allows('posts.publish')).toBe(true);

    expect(getPermissions).toHaveBeenCalledTimes(1);
  });

  it('still works standalone (no context): each allows() may re-fetch', async () => {
    // Without a per-request store there is nowhere to memoize across separate
    // top-level allows() calls — but correctness is unchanged.
    const getPermissions = vi.fn(() => ['posts.*']);
    const provider: PermissionProvider = { hasPermission: () => false, getPermissions };
    const gate = new Gate(new PolicyRegistry(), {}, undefined, undefined, provider);

    const bound = gate.forUser({ id: 1 });
    expect(await bound.allows('posts.update')).toBe(true);
    expect(await bound.allows('posts.delete')).toBe(true);
    // No request scope → no shared memo, but verdicts are correct.
    expect(getPermissions).toHaveBeenCalledTimes(2);
  });

  it('distinct users in one request each get their own fetch', async () => {
    const getPermissions = vi.fn((user: unknown) => (user as { perms: string[] }).perms);
    const provider: PermissionProvider = { hasPermission: () => false, getPermissions };
    const { accessor } = contextWithStore({ type: 'user', id: 5 });
    const gate = new Gate(new PolicyRegistry(), {}, accessor, undefined, provider);

    // forUser bypasses context but should still share the request cache when present.
    const a = gate.forUser({ id: 'a', perms: ['posts.*'] });
    const b = gate.forUser({ id: 'b', perms: ['comments.*'] });

    expect(await a.allows('posts.update')).toBe(true);
    expect(await a.allows('posts.delete')).toBe(true); // same user → cached
    expect(await b.allows('comments.delete')).toBe(true); // different user → its own fetch

    expect(getPermissions).toHaveBeenCalledTimes(2);
  });
});
