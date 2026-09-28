import 'reflect-metadata';
import { HTTP } from '@cerbos/http';
import { describe, expect, it } from 'vitest';
import { CerbosDecisionProvider } from '../src/cerbos/index.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import { eq } from '../src/scope.js';

/**
 * Against a REAL Cerbos PDP loaded with `test/fixtures/cerbos/*.yaml`:
 *
 *   docker run --rm -d --name authz-cerbos -p 3592:3592 \
 *     -v "$PWD/test/fixtures/cerbos:/policies:ro" ghcr.io/cerbos/cerbos:0.55.0 server
 *   CERBOS_TEST_URL=http://127.0.0.1:3592 pnpm vitest run test/cerbos.integration.spec.ts
 *
 * Skipped when `CERBOS_TEST_URL` is not set (the default `pnpm test` needs no Docker).
 */
const url = process.env.CERBOS_TEST_URL;
const describeCerbos = url ? describe : describe.skip;

class Doc {
  constructor(
    readonly id: string,
    readonly owner: string,
    readonly status = 'draft',
  ) {}
}

@Policy(Doc)
class DocPolicy {
  // Would allow everything — proves Cerbos' verdict wins.
  update() {
    return true;
  }
  scope() {
    return eq('never', 'used');
  }
}

describeCerbos('CerbosDecisionProvider against a real Cerbos PDP', () => {
  const provider = new CerbosDecisionProvider({
    client: new HTTP(url ?? 'http://127.0.0.1:3592'),
    principal: (u) => (u ? { id: (u as { id: string }).id, roles: ['user'] } : undefined),
    resource: (_ability, r) =>
      r instanceof Doc
        ? { kind: 'doc', id: r.id, attr: { owner: r.owner, status: r.status } }
        : undefined,
    scope: { resource: (entity) => (entity === Doc ? { kind: 'doc' } : undefined) },
  });
  const registry = new PolicyRegistry();
  registry.register(new DocPolicy() as never);
  const gate = new Gate(registry, {}, undefined, undefined, undefined, undefined, provider);

  it('allows / denies single checks (Cerbos overrides the permissive policy)', async () => {
    expect(await gate.forUser({ id: 'u1' }).allows('update', new Doc('d1', 'u1'))).toBe(true);
    expect(await gate.forUser({ id: 'u2' }).allows('update', new Doc('d1', 'u1'))).toBe(false);
    expect(await gate.forUser({ id: 'u2' }).allows('read', new Doc('d1', 'u1'))).toBe(true);
  });

  it('batches allowsMany into one CheckResources call', async () => {
    const results = await gate.forUser({ id: 'u1' }).allowsMany([
      { ability: 'update', resource: new Doc('a', 'u1') },
      { ability: 'update', resource: new Doc('b', 'u2') },
      { ability: 'delete', resource: new Doc('a', 'u1') },
      { ability: 'delete', resource: new Doc('c', 'u1', 'published') },
    ]);
    expect(results.map((r) => r.allowed)).toEqual([true, false, true, false]);
  });

  it('maps PlanResources onto gate.scope()', async () => {
    expect(await gate.forUser({ id: 'u1' }).scope(Doc, 'read')).toEqual({ kind: 'all' });
    expect(await gate.forUser({ id: 'u1' }).scope(Doc, 'update')).toEqual({
      kind: 'condition',
      field: 'owner',
      op: 'eq',
      value: 'u1',
    });
    const del = await gate.forUser({ id: 'u1' }).scope(Doc, 'delete');
    expect(del).toEqual({
      kind: 'and',
      nodes: [
        { kind: 'condition', field: 'owner', op: 'eq', value: 'u1' },
        { kind: 'condition', field: 'status', op: 'ne', value: 'published' },
      ],
    });
    // An action with no rule → always denied.
    expect(await gate.forUser({ id: 'u1' }).scope(Doc, 'archive')).toEqual({ kind: 'none' });
  });

  it('fails closed when the PDP is unreachable', async () => {
    const down = new CerbosDecisionProvider({
      client: new HTTP('http://127.0.0.1:1'),
      principal: () => ({ id: 'u1', roles: ['user'] }),
      resource: (_a, r) => (r instanceof Doc ? { kind: 'doc', id: r.id } : undefined),
    });
    expect(await down.decide({ id: 'u1' }, 'read', new Doc('d', 'u1'))).toBe(false);
  });
});
