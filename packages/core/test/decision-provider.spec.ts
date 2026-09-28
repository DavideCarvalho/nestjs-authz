import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { describe, expect, it, vi } from 'vitest';
import type { DecisionProvider } from '../src/decision-provider.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import { eq, scopeNone } from '../src/scope.js';
import { DECISION_PROVIDER } from '../src/tokens.js';
import type { AuthzModuleOptions } from '../src/types.js';

class Post {
  constructor(
    readonly id: number,
    readonly ownerId = 1,
  ) {}
}

interface U {
  id: number;
  admin?: boolean;
}

@Policy(Post)
class PostPolicy {
  update(user: U, post: Post) {
    return user.id === post.ownerId;
  }
  scope(user: U) {
    return eq('ownerId', user.id);
  }
}

function gate(
  decision: DecisionProvider | undefined,
  options: AuthzModuleOptions = {},
  permissions?: PermissionProvider,
): Gate {
  const registry = new PolicyRegistry();
  registry.register(new PostPolicy() as never);
  return new Gate(registry, options, undefined, undefined, permissions, undefined, decision);
}

describe('DecisionProvider seam', () => {
  it('an explicit deny overrides a policy that would allow', async () => {
    const provider: DecisionProvider = { decide: () => false };
    expect(await gate(provider).forUser({ id: 1 }).allows('update', new Post(1))).toBe(false);
  });

  it('an explicit allow overrides a policy that would deny', async () => {
    const provider: DecisionProvider = { decide: () => true };
    expect(await gate(provider).forUser({ id: 2 }).allows('update', new Post(1))).toBe(true);
  });

  it('abstaining (undefined) falls through to the policy', async () => {
    const provider: DecisionProvider = { decide: () => undefined };
    const g = gate(provider);
    expect(await g.forUser({ id: 1 }).allows('update', new Post(1))).toBe(true);
    expect(await g.forUser({ id: 2 }).allows('update', new Post(1))).toBe(false);
  });

  it('receives the user, ability and resource', async () => {
    const decide = vi.fn().mockReturnValue(undefined);
    const post = new Post(9);
    await gate({ decide }).forUser({ id: 1 }).allows('update', post);
    expect(decide).toHaveBeenCalledWith({ id: 1 }, 'update', post);
  });

  it('runs AFTER superAdmin: a super-admin grant never reaches the provider', async () => {
    const decide = vi.fn().mockReturnValue(false);
    const g = gate({ decide }, { superAdmin: (u) => (u as U).admin === true || undefined });
    expect(await g.forUser({ id: 5, admin: true }).allows('update', new Post(1))).toBe(true);
    expect(decide).not.toHaveBeenCalled();
  });

  it('superAdmin receives the resource (to scope a bypass)', async () => {
    const superAdmin = vi.fn().mockReturnValue(undefined);
    const post = new Post(1);
    await gate(undefined, { superAdmin }).forUser({ id: 1 }).allows('update', post);
    expect(superAdmin).toHaveBeenCalledWith({ id: 1 }, 'update', post);
  });

  it('a deny beats a permission-provider grant (the provider runs first)', async () => {
    const permissions: PermissionProvider = { hasPermission: () => true };
    const g = gate({ decide: () => false }, {}, permissions);
    expect(await g.forUser({ id: 1 }).allows('update', new Post(1))).toBe(false);
  });

  it('is consulted for anonymous callers (user undefined) and may allow them', async () => {
    const decide = vi.fn().mockReturnValue(true);
    expect(await gate({ decide }).forUser(undefined).allows('update', new Post(1))).toBe(true);
    expect(decide).toHaveBeenCalledWith(undefined, 'update', expect.any(Post));
  });

  it('authorize() surfaces reason "decision-provider" and the deny message', async () => {
    const g = gate({ decide: () => ({ allowed: false, message: 'blocked by PDP' }) });
    const err = await g
      .forUser({ id: 1 })
      .authorize('update', new Post(1))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ForbiddenException);
    const body = (err as ForbiddenException).getResponse() as Record<string, unknown>;
    expect(body).toMatchObject({ reason: 'decision-provider', message: 'blocked by PDP' });
  });

  it('allowsMany calls decideMany ONCE and uses its verdicts in order', async () => {
    const decide = vi.fn();
    const decideMany = vi.fn().mockResolvedValue([true, undefined, false]);
    const results = await gate({ decide, decideMany })
      .forUser({ id: 2 })
      .allowsMany([
        { ability: 'update', resource: new Post(1) },
        { ability: 'update', resource: new Post(2, 2) }, // abstain → policy (owner) → true
        { ability: 'update', resource: new Post(3, 2) },
      ]);
    expect(results.map((r) => r.allowed)).toEqual([true, true, false]);
    expect(decideMany).toHaveBeenCalledOnce();
    expect(decide).not.toHaveBeenCalled();
  });

  it('allowsMany falls back to per-item decide when decideMany throws', async () => {
    const decide = vi.fn().mockReturnValue(true);
    const decideMany = vi.fn().mockRejectedValue(new Error('down'));
    const results = await gate({ decide, decideMany })
      .forUser({ id: 2 })
      .allowsMany([{ ability: 'update', resource: new Post(1) }]);
    expect(results[0]?.allowed).toBe(true);
    expect(decide).toHaveBeenCalledOnce();
  });

  it('gate.scope uses planScope, and falls back to the policy scope when it abstains', async () => {
    const planned = gate({ decide: () => undefined, planScope: () => scopeNone });
    expect(await planned.forUser({ id: 1 }).scope(Post)).toEqual(scopeNone);

    const abstain = gate({ decide: () => undefined, planScope: () => undefined });
    expect(await abstain.forUser({ id: 1 }).scope(Post)).toEqual(eq('ownerId', 1));
  });

  it('gate.scope: superAdmin wins over planScope and receives the entity', async () => {
    const planScope = vi.fn().mockReturnValue(scopeNone);
    const superAdmin = vi.fn().mockReturnValue(true);
    const g = gate({ decide: () => undefined, planScope }, { superAdmin });
    expect(await g.forUser({ id: 1 }).scope(Post)).toEqual({ kind: 'all' });
    expect(planScope).not.toHaveBeenCalled();
    expect(superAdmin).toHaveBeenCalledWith({ id: 1 }, 'viewAny', Post);
  });

  it('is discovered through the DECISION_PROVIDER token in a Nest module', async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        PolicyRegistry,
        Gate,
        {
          provide: DECISION_PROVIDER,
          useValue: { decide: () => false } satisfies DecisionProvider,
        },
      ],
    }).compile();
    moduleRef.get(PolicyRegistry).register(new PostPolicy() as never);
    expect(await moduleRef.get(Gate).forUser({ id: 1 }).allows('update', new Post(1))).toBe(false);
  });
});
