import { describe, expect, it, vi } from 'vitest';
import {
  AbilityStore,
  createCan,
  createCanBatch,
  hydrateFromInertiaProps,
  hydrateResource,
} from '../src/index.js';

describe('client AbilityStore + can() — hydrated reads, no request', () => {
  it('hydrates class abilities from props.auth.can and reads synchronously', () => {
    const store = new AbilityStore();
    hydrateFromInertiaProps(store, {
      auth: { can: { 'post.create': true, 'access-admin': false } },
    });
    const can = createCan(store);
    expect(can('post.create')).toBe(true);
    expect(can('access-admin')).toBe(false);
  });

  it('does NOT fetch when the ability is known (cache hit)', () => {
    const store = new AbilityStore();
    hydrateFromInertiaProps(store, { auth: { can: { 'post.create': true } } });
    const fetchImpl = vi.fn();
    const can = createCan(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(can('post.create')).toBe(true);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('reads per-resource maps keyed by type#id, no fetch', () => {
    const store = new AbilityStore();
    hydrateResource(store, { type: 'Post', id: 7 }, { update: true, delete: false });
    const fetchImpl = vi.fn();
    const can = createCan(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(can('update', { type: 'Post', id: 7 })).toBe(true);
    expect(can('delete', { type: 'Post', id: 7 })).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("denies synchronously on a cache miss with fallback 'deny' (default)", () => {
    const store = new AbilityStore();
    const fetchImpl = vi.fn();
    const can = createCan(store, { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(can('unknown.ability')).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("falls back to fetch ONLY when unknown and fallback is 'fetch'", async () => {
    const store = new AbilityStore();
    hydrateFromInertiaProps(store, { auth: { can: { known: true } } });
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ allowed: true }),
    });
    const can = createCan(store, {
      fallback: 'fetch',
      endpoint: '/authz/can',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    // known → sync, no fetch
    expect(can('known')).toBe(true);
    expect(fetchImpl).not.toHaveBeenCalled();

    // unknown → promise via fetch
    const result = can('mystery', { type: 'Post', id: 3 });
    expect(result).toBeInstanceOf(Promise);
    await expect(result).resolves.toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/authz/can');
    expect(JSON.parse(init.body as string)).toEqual({
      ability: 'mystery',
      resource: { type: 'Post', id: 3 },
    });
  });

  it('warns (once) when a resource-bound ability falls through to the fetch fallback', async () => {
    const store = new AbilityStore();
    const fetchImpl = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({ allowed: false }) });
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const can = createCan(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    // Resource-bound miss → cannot be resolved server-side → warns and denies.
    await expect(can('update', { type: 'Post', id: 7 })).resolves.toBe(false);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain('per-instance');

    // Subsequent resource misses do not re-warn (warn-once).
    await can('delete', { type: 'Post', id: 8 });
    expect(warn).toHaveBeenCalledTimes(1);

    // A class-level (resource-less) miss does NOT warn.
    await can('class.level.miss');
    expect(warn).toHaveBeenCalledTimes(1);

    warn.mockRestore();
  });

  it('fetch fallback returns false on a non-ok response', async () => {
    const store = new AbilityStore();
    const fetchImpl = vi.fn().mockResolvedValue({ ok: false, json: async () => ({}) });
    const can = createCan(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await expect(can('nope')).resolves.toBe(false);
  });

  it('store.peek / has report cached verdicts without I/O', () => {
    const store = new AbilityStore();
    store.setClassAbilities({ 'post.create': true });
    expect(store.has('post.create')).toBe(true);
    expect(store.has('post.delete')).toBe(false);
    expect(store.peek('post.create')).toBe(true);
    expect(store.peek('post.delete')).toBeUndefined();
    store.clear();
    expect(store.has('post.create')).toBe(false);
  });
});

describe('createCanBatch — one round-trip for many checks', () => {
  it('answers cache hits synchronously and never fetches when all are hydrated', async () => {
    const store = new AbilityStore();
    hydrateFromInertiaProps(store, { auth: { can: { a: true, b: false } } });
    const fetchImpl = vi.fn();
    const canBatch = createCanBatch(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const results = await canBatch([{ ability: 'a' }, { ability: 'b' }]);
    expect(results).toEqual([
      { ability: 'a', allowed: true },
      { ability: 'b', allowed: false },
    ]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('POSTs ONLY the cache-misses, in a single array request, and merges in order', async () => {
    const store = new AbilityStore();
    hydrateFromInertiaProps(store, { auth: { can: { known: true } } });
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      // server echoes ability + verdict per item
      json: async () => [
        { ability: 'miss1', allowed: true },
        { ability: 'miss2', allowed: false },
      ],
    });
    const canBatch = createCanBatch(store, {
      fallback: 'fetch',
      endpoint: '/authz/can',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const results = await canBatch([
      { ability: 'known' },
      { ability: 'miss1' },
      { ability: 'miss2' },
    ]);

    expect(results).toEqual([
      { ability: 'known', allowed: true },
      { ability: 'miss1', allowed: true },
      { ability: 'miss2', allowed: false },
    ]);

    // ONE request for the two misses (not two).
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/authz/can');
    expect(JSON.parse(init.body as string)).toEqual([
      { ability: 'miss1', resource: null },
      { ability: 'miss2', resource: null },
    ]);
  });

  it("denies misses synchronously under fallback 'deny' (default), no fetch", async () => {
    const store = new AbilityStore();
    hydrateFromInertiaProps(store, { auth: { can: { yes: true } } });
    const fetchImpl = vi.fn();
    const canBatch = createCanBatch(store, { fetchImpl: fetchImpl as unknown as typeof fetch });

    const results = await canBatch([{ ability: 'yes' }, { ability: 'no' }]);
    expect(results).toEqual([
      { ability: 'yes', allowed: true },
      { ability: 'no', allowed: false },
    ]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('carries resource shims through the batch request and matches per-instance hits', async () => {
    const store = new AbilityStore();
    hydrateResource(store, { type: 'Post', id: 1 }, { update: true });
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{ ability: 'update', resource: { type: 'Post', id: 2 }, allowed: false }],
    });
    const canBatch = createCanBatch(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const results = await canBatch([
      { ability: 'update', resource: { type: 'Post', id: 1 } }, // cache hit
      { ability: 'update', resource: { type: 'Post', id: 2 } }, // miss → fetched
    ]);

    expect(results).toEqual([
      { ability: 'update', resource: { type: 'Post', id: 1 }, allowed: true },
      { ability: 'update', resource: { type: 'Post', id: 2 }, allowed: false },
    ]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual([
      { ability: 'update', resource: { type: 'Post', id: 2 } },
    ]);
  });

  it('denies all misses on a non-ok response', async () => {
    const store = new AbilityStore();
    const fetchImpl = vi.fn().mockResolvedValue({ ok: false, json: async () => [] });
    const canBatch = createCanBatch(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const results = await canBatch([{ ability: 'a' }, { ability: 'b' }]);
    expect(results).toEqual([
      { ability: 'a', allowed: false },
      { ability: 'b', allowed: false },
    ]);
  });

  it('an empty batch returns an empty array without fetching', async () => {
    const store = new AbilityStore();
    const fetchImpl = vi.fn();
    const canBatch = createCanBatch(store, {
      fallback: 'fetch',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(await canBatch([])).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
