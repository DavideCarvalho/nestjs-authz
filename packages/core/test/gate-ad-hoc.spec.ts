import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { AbilityNotResolvedException } from '../src/errors/exceptions.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';

function makeGate(): Gate {
  return new Gate(new PolicyRegistry(), {}, undefined);
}

describe('ad-hoc gates', () => {
  it('define + allows resolves a model-less ability', async () => {
    const gate = makeGate();
    gate.define('access-admin', (user) => (user as { role?: string }).role === 'staff');
    expect(await gate.forUser({ role: 'staff' }).allows('access-admin')).toBe(true);
    expect(await gate.forUser({ role: 'user' }).allows('access-admin')).toBe(false);
  });

  it('hasGate reflects registration', () => {
    const gate = makeGate();
    expect(gate.hasGate('x')).toBe(false);
    gate.define('x', () => true);
    expect(gate.hasGate('x')).toBe(true);
  });

  it('throws AbilityNotResolvedException for unknown abilities', async () => {
    const gate = makeGate();
    await expect(gate.forUser({}).allows('nope')).rejects.toBeInstanceOf(
      AbilityNotResolvedException,
    );
  });

  it('explicit-user path works with no context accessor present', async () => {
    const gate = makeGate();
    gate.define('ping', (user) => user !== undefined);
    // forUser supplies the user directly — no CONTEXT_ACCESSOR injected.
    expect(await gate.forUser({ id: 1 }).allows('ping')).toBe(true);
  });

  it('context-less current user is treated as unauthenticated → deny', async () => {
    const gate = makeGate();
    gate.define('ping', () => true);
    // No forUser, no context accessor → NO_USER → deny.
    expect(await gate.allows('ping')).toBe(false);
  });
});
