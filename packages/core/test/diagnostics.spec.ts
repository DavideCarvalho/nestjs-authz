import 'reflect-metadata';
import diagnostics_channel from 'node:diagnostics_channel';
import { afterEach, describe, expect, it } from 'vitest';
import { AUTHZ_DECISION_CHANNEL, type AuthzDecisionDiagnostic } from '../src/diagnostics.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';

function makeGate(): Gate {
  return new Gate(new PolicyRegistry(), {}, undefined);
}

/** Subscribe to the decision channel for the duration of a test; returns captured payloads. */
function captureDecisions(): { decisions: AuthzDecisionDiagnostic[]; stop: () => void } {
  const decisions: AuthzDecisionDiagnostic[] = [];
  const channel = diagnostics_channel.channel(AUTHZ_DECISION_CHANNEL);
  const onMessage = (msg: unknown) => decisions.push(msg as AuthzDecisionDiagnostic);
  channel.subscribe(onMessage);
  return { decisions, stop: () => channel.unsubscribe(onMessage) };
}

describe('authz decision diagnostics channel', () => {
  let stop: (() => void) | undefined;
  afterEach(() => {
    stop?.();
    stop = undefined;
  });

  it('publishes a payload on an allow', async () => {
    const gate = makeGate();
    gate.define('access-admin', (user) => (user as { role?: string }).role === 'staff');
    const cap = captureDecisions();
    stop = cap.stop;

    const allowed = await gate
      .forUser({ type: 'User', id: 7, role: 'staff' })
      .allows('access-admin');

    expect(allowed).toBe(true);
    expect(cap.decisions).toHaveLength(1);
    expect(cap.decisions[0]).toMatchObject({
      v: 1,
      ability: 'access-admin',
      allowed: true,
      reason: 'gate',
      userRef: 'User#7',
      resourceType: null,
      resourceId: null,
    });
  });

  it('publishes a payload on a deny', async () => {
    const gate = makeGate();
    gate.define('publish', () => false);
    const cap = captureDecisions();
    stop = cap.stop;

    const allowed = await gate.forUser({ id: 1 }).allows('publish');

    expect(allowed).toBe(false);
    expect(cap.decisions).toHaveLength(1);
    expect(cap.decisions[0]).toMatchObject({
      ability: 'publish',
      allowed: false,
      reason: 'gate',
    });
  });

  it('does not publish when an ability cannot be resolved (it throws)', async () => {
    const gate = makeGate();
    const cap = captureDecisions();
    stop = cap.stop;

    await expect(gate.forUser({}).allows('unknown')).rejects.toThrow();
    expect(cap.decisions).toHaveLength(0);
  });
});
