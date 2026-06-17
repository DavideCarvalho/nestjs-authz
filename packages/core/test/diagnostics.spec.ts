import 'reflect-metadata';
import diagnostics_channel from 'node:diagnostics_channel';
import { type DiagnosticEvent, channelName } from '@dudousxd/nestjs-diagnostics';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuthzDecisionDiagnostic } from '../src/diagnostics.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';

/** The standard aviary channel authz emits decisions on: `aviary:authz:decision`. */
const DECISION_CHANNEL = channelName('authz', 'decision');

function makeGate(): Gate {
  return new Gate(new PolicyRegistry(), {}, undefined);
}

/** Subscribe to the decision channel for the duration of a test; returns captured envelopes. */
function captureDecisions(): { envelopes: DiagnosticEvent[]; stop: () => void } {
  const envelopes: DiagnosticEvent[] = [];
  const channel = diagnostics_channel.channel(DECISION_CHANNEL);
  const onMessage = (msg: unknown) => envelopes.push(msg as DiagnosticEvent);
  channel.subscribe(onMessage);
  return { envelopes, stop: () => channel.unsubscribe(onMessage) };
}

describe('authz decision diagnostics channel', () => {
  let stop: (() => void) | undefined;
  afterEach(() => {
    stop?.();
    stop = undefined;
  });

  it('publishes an aviary envelope on an allow', async () => {
    const gate = makeGate();
    gate.define('access-admin', (user) => (user as { role?: string }).role === 'staff');
    const cap = captureDecisions();
    stop = cap.stop;

    const allowed = await gate
      .forUser({ type: 'User', id: 7, role: 'staff' })
      .allows('access-admin');

    expect(allowed).toBe(true);
    expect(cap.envelopes).toHaveLength(1);
    // Wire contract: the standard envelope wraps the authz payload.
    expect(cap.envelopes[0]).toMatchObject({ lib: 'authz', event: 'decision' });
    expect(typeof cap.envelopes[0]?.ts).toBe('number');
    expect(cap.envelopes[0]?.payload).toMatchObject({
      v: 1,
      ability: 'access-admin',
      allowed: true,
      reason: 'gate',
      userRef: 'User#7',
      resourceType: null,
      resourceId: null,
    } satisfies AuthzDecisionDiagnostic);
  });

  it('publishes a payload on a deny', async () => {
    const gate = makeGate();
    gate.define('publish', () => false);
    const cap = captureDecisions();
    stop = cap.stop;

    const allowed = await gate.forUser({ id: 1 }).allows('publish');

    expect(allowed).toBe(false);
    expect(cap.envelopes).toHaveLength(1);
    expect(cap.envelopes[0]?.payload).toMatchObject({
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
    expect(cap.envelopes).toHaveLength(0);
  });
});
