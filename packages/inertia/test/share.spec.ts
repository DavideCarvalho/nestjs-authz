import 'reflect-metadata';
import { AuthzModule, Gate, PolicyFor, PolicyIndex } from '@dudousxd/nestjs-authz';
import { AuthorizationModule, Policy } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { createAuthzShare } from '../src/share.js';

class Post {}

@PolicyFor(Post)
class PostPolicy {
  create(user: { id: number } | null) {
    return user?.id === 1;
  }
  publish() {
    return false;
  }
  // Instance method (arity 2). Must NOT be dispatched against the class:
  // doing so would call it with `post` = the Post constructor and write a
  // bogus class-level verdict into props.auth.can.
  update(_user: { id: number } | null, _post: Post) {
    return true;
  }
}

/** An official policy with no resource link: keyed by its class name. */
@Policy()
class ReportPolicy {
  export(user: { id: number } | null) {
    return user?.id === 1;
  }
}

// The official guard's user: always #1.
const official = AuthorizationModule.forRoot({ getUser: () => ({ id: 1 }) });

describe('createAuthzShare — resolves class abilities into props.auth.can', () => {
  let gate: Gate;
  let policies: PolicyIndex;

  beforeEach(async () => {
    const mod = await Test.createTestingModule({
      imports: [official, AuthzModule.forRoot()],
      providers: [PostPolicy, ReportPolicy],
    }).compile();
    await mod.init();
    gate = mod.get(Gate);
    policies = mod.get(PolicyIndex);
    // Register an ad-hoc gate so we cover gate enumeration too.
    gate.define('access-admin', (user: { id: number } | null) => user?.id === 99);
  });

  it('nests the can map under auth.can with policy + gate verdicts', async () => {
    const share = createAuthzShare(gate.forUser({ id: 1 }), policies);
    const props = (await share()) as { auth: { can: Record<string, boolean> } };
    expect(props.auth.can['post.create']).toBe(true);
    expect(props.auth.can['post.publish']).toBe(false);
    expect(props.auth.can['access-admin']).toBe(false);
    // The instance method `update(user, post)` is NOT shared as a class ability.
    expect(props.auth.can['post.update']).toBeUndefined();
    expect(props.auth.can['report.export']).toBe(true);
    // Built-in policies are not resource abilities.
    expect(Object.keys(props.auth.can).some((k) => k.startsWith('role.'))).toBe(false);
  });

  it('honors a custom propKey and abilityNamer (bare method names)', async () => {
    const share = createAuthzShare(gate.forUser({ id: 1 }), policies, {
      propKey: 'abilities',
      abilityNamer: (_resource, method) => method,
    });
    const props = (await share()) as { abilities: { can: Record<string, boolean> } };
    expect(props.abilities.can.create).toBe(true);
    expect(props.abilities.can.publish).toBe(false);
  });
});
