import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import type { AfterHook } from '../src/types.js';

class Doc {
  constructor(
    public id: number,
    public ownerId: number,
  ) {}
}

// A policy whose `update` returns an EXPLICIT boolean (ownership), while `review`
// returns `undefined` (no opinion) so `after` may decide it.
@Policy(Doc)
class DocPolicy {
  update(user: { id: number }, doc: Doc) {
    return doc.ownerId === user.id;
  }
  review(_user: { id: number }, _doc: Doc): boolean | undefined {
    return undefined; // no opinion
  }
}

function makeGate(after?: AfterHook): Gate {
  const registry = new PolicyRegistry();
  registry.register(new DocPolicy());
  return new Gate(registry, after ? { after } : {}, undefined);
}

describe('global after() hook (Laravel Gate::after semantics)', () => {
  it('observes every reached decision with the resolved verdict', async () => {
    const after = vi.fn<AfterHook>(() => undefined);
    const gate = makeGate(after);
    const doc = new Doc(1, 1);
    await gate.forUser({ id: 1 }).allows('update', doc); // explicit allow
    expect(after).toHaveBeenCalledWith({ id: 1 }, 'update', true, doc);
  });

  it('does NOT override an explicit allow (observe-only when policy decided)', async () => {
    const after = makeGate(() => false); // tries to deny
    const doc = new Doc(1, 1); // owner → policy explicitly allows
    expect(await after.forUser({ id: 1 }).allows('update', doc)).toBe(true);
  });

  it('does NOT override an explicit deny (observe-only when policy decided)', async () => {
    const gate = makeGate(() => true); // tries to grant
    const doc = new Doc(1, 999); // not owner → policy explicitly denies
    expect(await gate.forUser({ id: 1 }).allows('update', doc)).toBe(false);
  });

  it('CAN grant when the policy returned no opinion (undefined)', async () => {
    const gate = makeGate((_u, _a, result) => {
      expect(result).toBeUndefined();
      return true;
    });
    expect(await gate.forUser({ id: 1 }).allows('review', new Doc(1, 1))).toBe(true);
  });

  it('CAN deny when the policy returned no opinion (undefined)', async () => {
    const gate = makeGate(() => false);
    expect(await gate.forUser({ id: 1 }).allows('review', new Doc(1, 1))).toBe(false);
  });

  it('no-opinion policy + no override → default deny (unchanged)', async () => {
    const gate = makeGate(() => undefined);
    expect(await gate.forUser({ id: 1 }).allows('review', new Doc(1, 1))).toBe(false);
  });

  it('an after-supplied deny message reaches authorize()', async () => {
    const gate = makeGate(() => ({ allowed: false, message: 'after says no' }));
    try {
      await gate.forUser({ id: 1 }).authorize('review', new Doc(1, 1));
      throw new Error('expected throw');
    } catch (err) {
      const body = (err as { getResponse(): Record<string, unknown> }).getResponse();
      expect(body.message).toBe('after says no');
      expect(body.reason).toBe('after');
    }
  });
});
