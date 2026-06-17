import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { AbilityNotResolvedException } from '../src/errors/exceptions.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';

class Doc {
  constructor(
    public id: number,
    public ownerId: number,
  ) {}
}

@Policy(Doc)
class DocPolicy {
  before(user: { isAdmin?: boolean; banned?: boolean }) {
    if (user.isAdmin) return true; // bypass-allow
    if (user.banned) return false; // bypass-deny
    // otherwise: undefined → fall through
  }
  update(user: { id: number }, doc: Doc) {
    return doc.ownerId === user.id;
  }
}

function makeGate(superAdmin?: (u: unknown) => boolean): Gate {
  const registry = new PolicyRegistry();
  registry.register(new DocPolicy());
  return new Gate(registry, superAdmin ? { superAdmin } : {}, undefined);
}

describe('before / superAdmin hooks', () => {
  it('per-policy before grants admin regardless of ownership', async () => {
    const gate = makeGate();
    const admin = { id: 5, isAdmin: true };
    const doc = new Doc(1, 999);
    expect(await gate.forUser(admin).allows('update', doc)).toBe(true);
  });

  it('per-policy before can deny outright (banned)', async () => {
    const gate = makeGate();
    const owner = { id: 1, banned: true };
    const doc = new Doc(1, 1); // would otherwise pass ownership
    expect(await gate.forUser(owner).allows('update', doc)).toBe(false);
  });

  it('before returning void falls through to the ability method', async () => {
    const gate = makeGate();
    const owner = { id: 1 };
    const doc = new Doc(1, 1);
    expect(await gate.forUser(owner).allows('update', doc)).toBe(true);
  });

  it('global superAdmin hook short-circuits before the policy', async () => {
    const gate = makeGate((u) => (u as { root?: boolean }).root === true);
    const root = { id: 0, root: true };
    const doc = new Doc(1, 999);
    expect(await gate.forUser(root).allows('update', doc)).toBe(true);
  });

  // --- P10: `before` may only answer abilities the policy actually defines ---

  it('before does NOT grant an ability the policy never defines (frobnicate)', async () => {
    // DocPolicy has a `before` that grants admins, but no `frobnicate` method.
    const gate = makeGate();
    const admin = { id: 5, isAdmin: true };
    const doc = new Doc(1, 999);

    // before would return true, but the policy doesn't define `frobnicate` →
    // must fall through to AbilityNotResolved, NOT be granted by `before`.
    await expect(gate.forUser(admin).allows('frobnicate', doc)).rejects.toBeInstanceOf(
      AbilityNotResolvedException,
    );
  });

  it('before still gates a defined ability (admin granted on update)', async () => {
    const gate = makeGate();
    const admin = { id: 5, isAdmin: true };
    const doc = new Doc(1, 999);
    // `update` IS defined → before runs and grants.
    expect(await gate.forUser(admin).allows('update', doc)).toBe(true);
  });
});
