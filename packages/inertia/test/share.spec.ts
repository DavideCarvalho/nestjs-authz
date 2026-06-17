import 'reflect-metadata';
import { AuthzModule, Gate, Policy, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { CONTEXT_ACCESSOR } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { createAuthzShare } from '../src/share.js';

class Post {}

@Policy(Post)
class PostPolicy {
  create(user: { id: number } | undefined) {
    return user?.id === 1;
  }
  publish() {
    return false;
  }
  // Instance method (arity 2). Must NOT be dispatched against the class:
  // doing so would call it with `post` = the Post constructor and write a
  // bogus class-level verdict into props.auth.can.
  update(_user: { id: number } | undefined, _post: Post) {
    return true;
  }
}

const stubContext = { userRef: () => ({ type: 'User', id: 1 }) };

describe('createAuthzShare — resolves class abilities into props.auth.can', () => {
  let gate: Gate;
  let policies: PolicyRegistry;

  beforeEach(async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot({ policies: [PostPolicy] })],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    await mod.init();
    gate = mod.get(Gate);
    policies = mod.get(PolicyRegistry);
    // Register an ad-hoc gate so we cover gate enumeration too.
    gate.define('access-admin', (user: { id: number } | undefined) => user?.id === 99);
  });

  it('nests the can map under auth.can with policy + gate verdicts', async () => {
    const share = createAuthzShare(gate, policies);
    const props = (await share()) as { auth: { can: Record<string, boolean> } };
    expect(props.auth.can['post.create']).toBe(true);
    expect(props.auth.can['post.publish']).toBe(false);
    expect(props.auth.can['access-admin']).toBe(false);
    // The instance method `update(user, post)` is NOT shared as a class ability.
    expect(props.auth.can['post.update']).toBeUndefined();
  });

  it('honors a custom propKey and abilityNamer (bare method names)', async () => {
    const share = createAuthzShare(gate, policies, {
      propKey: 'abilities',
      abilityNamer: (_resource, method) => method,
    });
    const props = (await share()) as { abilities: { can: Record<string, boolean> } };
    expect(props.abilities.can.create).toBe(true);
    expect(props.abilities.can.publish).toBe(false);
  });
});
