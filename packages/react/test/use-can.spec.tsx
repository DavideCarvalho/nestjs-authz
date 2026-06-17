import { AbilityStore } from '@dudousxd/nestjs-authz-client';
import { cleanup, render, renderHook, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Can } from '../src/can.js';
import { AuthzProvider } from '../src/provider.js';
import { useCan } from '../src/use-can.js';

// `globals: false` means RTL's auto-cleanup afterEach is not registered — do it here.
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function wrapperWith(store: AbilityStore) {
  return ({ children }: { children: ReactNode }) => (
    <AuthzProvider store={store}>{children}</AuthzProvider>
  );
}

describe('useCan — synchronous reads from a hydrated store', () => {
  it('returns true/false for hydrated class abilities with NO fetch', () => {
    const store = new AbilityStore().setClassAbilities({
      'post.create': true,
      'access-admin': false,
    });
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const { result, rerender } = renderHook(({ ability }: { ability: string }) => useCan(ability), {
      wrapper: wrapperWith(store),
      initialProps: { ability: 'post.create' },
    });

    expect(result.current.allowed).toBe(true);
    expect(result.current.loading).toBe(false);

    rerender({ ability: 'access-admin' });
    expect(result.current.allowed).toBe(false);

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('reads per-resource verdicts keyed by type#id, synchronously', () => {
    const store = new AbilityStore().setResourceAbilities(
      { type: 'Post', id: 7 },
      { update: true, delete: false },
    );
    const { result } = renderHook(() => useCan('update', { type: 'Post', id: 7 }), {
      wrapper: wrapperWith(store),
    });
    expect(result.current.allowed).toBe(true);
    expect(result.current.loading).toBe(false);
  });

  it('denies a cache miss synchronously under the default deny fallback', () => {
    const store = new AbilityStore();
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const { result } = renderHook(() => useCan('unknown'), { wrapper: wrapperWith(store) });
    expect(result.current.allowed).toBe(false);
    expect(result.current.loading).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('fails closed (false) when no provider is mounted', () => {
    const { result } = renderHook(() => useCan('post.create'));
    expect(result.current.allowed).toBe(false);
    expect(result.current.loading).toBe(false);
  });

  it('reconciles a changed-but-cached resource SYNCHRONOUSLY (no stale verdict, no fetch)', () => {
    // postA is allowed, postB is denied — both already in the cache.
    const store = new AbilityStore()
      .setResourceAbilities({ type: 'Post', id: 'A' }, { update: true })
      .setResourceAbilities({ type: 'Post', id: 'B' }, { update: false });
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    // Record the verdict produced by EACH render pass (before effects commit),
    // so we can assert the synchronous render value and not the act()-flushed
    // one — the stale verdict was visible exactly for that pre-effect render.
    const renders: boolean[] = [];
    function Probe({ id }: { id: string }) {
      const { allowed } = useCan('update', { type: 'Post', id });
      renders.push(allowed);
      return null;
    }

    const { rerender } = render(
      <AuthzProvider store={store}>
        <Probe id="A" />
      </AuthzProvider>,
    );
    expect(renders.at(-1)).toBe(true);

    const before = renders.length;
    rerender(
      <AuthzProvider store={store}>
        <Probe id="B" />
      </AuthzProvider>,
    );

    // The FIRST render pass after the prop change must already show postB's
    // deny — no render in between showing postA's stale allow.
    expect(renders[before]).toBe(false);
    // ...and every subsequent render agrees (no flicker back).
    expect(renders.slice(before).every((v) => v === false)).toBe(true);

    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe('<Can> — conditional rendering', () => {
  it('renders children when allowed', () => {
    const store = new AbilityStore().setClassAbilities({ 'post.create': true });
    render(
      <AuthzProvider store={store}>
        <Can ability="post.create">
          <span>visible</span>
        </Can>
      </AuthzProvider>,
    );
    expect(screen.getByText('visible')).toBeTruthy();
  });

  it('hides children (and renders fallback) when denied', () => {
    const store = new AbilityStore().setClassAbilities({ 'post.create': false });
    render(
      <AuthzProvider store={store}>
        <Can ability="post.create" fallback={<span>locked</span>}>
          <span>visible</span>
        </Can>
      </AuthzProvider>,
    );
    expect(screen.queryByText('visible')).toBeNull();
    expect(screen.getByText('locked')).toBeTruthy();
  });

  it('keeps a seeded store across rerenders with an inline `options` object', () => {
    // No explicit store: provider seeds a fresh store from `abilities`. An inline
    // `options={{...}}` (new identity each render) must NOT rebuild that store.
    const renders: boolean[] = [];
    function Probe() {
      renders.push(useCan('post.create').allowed);
      return null;
    }
    const tree = (
      <AuthzProvider abilities={{ 'post.create': true }} options={{ fallback: 'deny' }}>
        <Probe />
      </AuthzProvider>
    );
    const { rerender } = render(tree);
    expect(renders.at(-1)).toBe(true);

    // Re-render with a brand-new inline options object identity.
    rerender(
      <AuthzProvider abilities={{ 'post.create': true }} options={{ fallback: 'deny' }}>
        <Probe />
      </AuthzProvider>,
    );
    expect(renders.every((v) => v === true)).toBe(true);
  });

  it('checks a resource via `of`', () => {
    const store = new AbilityStore().setResourceAbilities(
      { type: 'Post', id: 1 },
      { update: true },
    );
    render(
      <AuthzProvider store={store}>
        <Can ability="update" of={{ type: 'Post', id: 1 }}>
          <span>edit</span>
        </Can>
      </AuthzProvider>,
    );
    expect(screen.getByText('edit')).toBeTruthy();
  });
});
