import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import type { ContextAccessor, UserRef } from '../src/context-accessor.js';
import { Gate } from '../src/gate.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PolicyRegistry } from '../src/policy-registry.js';

/** A context accessor returning a fixed user ref, counting how often it is read. */
function countingContext(ref: UserRef | undefined): {
  accessor: ContextAccessor;
  counts: { userRef: number };
} {
  const counts = { userRef: 0 };
  const accessor: ContextAccessor = {
    traceId: () => undefined,
    tenantId: () => undefined,
    userRef: () => {
      counts.userRef += 1;
      return ref;
    },
    get: () => undefined,
  };
  return { accessor, counts };
}

describe('Gate.allowsMany — batch authorization in one pass', () => {
  it('returns the correct per-item verdict for each (ability, resource) pair', async () => {
    const gate = new Gate(new PolicyRegistry(), {});
    gate.define('ping', () => true);
    gate.define('pong', () => false);

    const results = await gate
      .forUser({ id: 1 })
      .allowsMany([{ ability: 'ping' }, { ability: 'pong' }]);

    expect(results).toEqual([
      { ability: 'ping', allowed: true },
      { ability: 'pong', allowed: false },
    ]);
  });

  it('preserves the resource on each result item', async () => {
    const gate = new Gate(new PolicyRegistry(), {});
    gate.define('touch', (_u, resource) => (resource as { ok?: boolean }).ok === true);

    const a = { ok: true };
    const b = { ok: false };
    const results = await gate.forUser({ id: 1 }).allowsMany([
      { ability: 'touch', resource: a },
      { ability: 'touch', resource: b },
    ]);

    expect(results).toEqual([
      { ability: 'touch', resource: a, allowed: true },
      { ability: 'touch', resource: b, allowed: false },
    ]);
  });

  it('resolves the context user ONCE for the whole batch', async () => {
    const { accessor, counts } = countingContext({ type: 'user', id: 5 });
    const gate = new Gate(new PolicyRegistry(), {}, accessor);
    gate.define('a', () => true);
    gate.define('b', () => true);
    gate.define('c', () => true);

    await gate.allowsMany([{ ability: 'a' }, { ability: 'b' }, { ability: 'c' }]);

    // One-at-a-time would read the ref 3 times; the batch reads it once.
    expect(counts.userRef).toBe(1);
  });

  it('resolves permissions ONCE for the whole batch (getPermissions called once)', async () => {
    const getPermissions = vi.fn(() => ['posts.*']);
    const provider: PermissionProvider = {
      hasPermission: () => false,
      getPermissions,
    };
    const gate = new Gate(new PolicyRegistry(), {}, undefined, undefined, provider);

    const results = await gate
      .forUser({ id: 1 })
      .allowsMany([
        { ability: 'posts.update' },
        { ability: 'posts.delete' },
        { ability: 'posts.publish' },
      ]);

    expect(results.map((r) => r.allowed)).toEqual([true, true, true]);
    // Without per-batch memoization, getPermissions would run once per item (3x).
    expect(getPermissions).toHaveBeenCalledTimes(1);
  });

  it('an empty batch returns an empty array', async () => {
    const gate = new Gate(new PolicyRegistry(), {});
    expect(await gate.forUser({ id: 1 }).allowsMany([])).toEqual([]);
  });

  it('Gate.allowsMany (context user) mirrors BoundGate.allowsMany', async () => {
    const { accessor } = countingContext({ type: 'user', id: 5 });
    const gate = new Gate(new PolicyRegistry(), {}, accessor);
    gate.define('a', () => true);
    gate.define('b', () => false);

    const results = await gate.allowsMany([{ ability: 'a' }, { ability: 'b' }]);
    expect(results).toEqual([
      { ability: 'a', allowed: true },
      { ability: 'b', allowed: false },
    ]);
  });
});
