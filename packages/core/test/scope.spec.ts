import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import type { ContextAccessor, UserRef } from '../src/context-accessor.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import {
  type ScopeConstraint,
  and,
  eq,
  normalizeScope,
  or,
  scopeAll,
  scopeNone,
  where,
} from '../src/scope.js';

class Post {}

interface Author {
  id: number;
  isAdmin?: boolean;
}

@Policy(Post)
class PostPolicy {
  // Per-user scope: a user sees only their own posts.
  scope(user: Author): ScopeConstraint {
    return eq('authorId', user.id);
  }
}

function registryWith(...policies: object[]): PolicyRegistry {
  const registry = new PolicyRegistry();
  for (const p of policies) registry.register(p as never);
  return registry;
}

function contextWith(ref: UserRef | undefined, tenantId?: string): ContextAccessor {
  return {
    traceId: () => undefined,
    tenantId: () => tenantId,
    userRef: () => ref,
    get: () => undefined,
  };
}

describe('scope AST builders', () => {
  it('eq builds an equality condition', () => {
    expect(eq('authorId', 7)).toEqual({ kind: 'condition', field: 'authorId', op: 'eq', value: 7 });
  });

  it('where omits value for null checks', () => {
    expect(where('deletedAt', 'isNull')).toEqual({
      kind: 'condition',
      field: 'deletedAt',
      op: 'isNull',
    });
  });

  it('and/or collapse single nodes and bottom out on empty', () => {
    const c = eq('a', 1);
    expect(and(c)).toEqual(c);
    expect(or(c)).toEqual(c);
    expect(and()).toEqual(scopeAll);
    expect(or()).toEqual(scopeNone);
    expect(and(eq('a', 1), eq('b', 2))).toEqual({
      kind: 'and',
      nodes: [eq('a', 1), eq('b', 2)],
    });
  });

  it('normalizeScope maps boolean/nullish sugar', () => {
    expect(normalizeScope(true)).toEqual(scopeAll);
    expect(normalizeScope(false)).toEqual(scopeNone);
    expect(normalizeScope(undefined)).toEqual(scopeNone);
    expect(normalizeScope(null)).toEqual(scopeNone);
    expect(normalizeScope(eq('a', 1))).toEqual(eq('a', 1));
  });
});

describe('Gate.scope — per-user constraint', () => {
  it('returns the policy scope constraint for the bound user', async () => {
    const gate = new Gate(registryWith(new PostPolicy()), {});
    const c = await gate.forUser({ id: 42 }).scope(Post);
    expect(c).toEqual(eq('authorId', 42));
  });

  it('resolves via the context user when no forUser is given', async () => {
    const policy = new PostPolicy();
    const gate = new Gate(
      registryWith(policy),
      { resolveUser: (ref) => ({ id: Number(ref.id) }) },
      contextWith({ type: 'user', id: 99 }),
    );
    const c = await gate.scope(Post);
    expect(c).toEqual(eq('authorId', 99));
  });
});

describe('Gate.scope — terminal verdicts', () => {
  it('super-admin → allow-all', async () => {
    const gate = new Gate(registryWith(new PostPolicy()), {
      superAdmin: (u: unknown) => (u as Author).isAdmin === true,
    });
    const c = await gate.forUser({ id: 1, isAdmin: true }).scope(Post);
    expect(c).toEqual(scopeAll);
  });

  it('anonymous → deny-all', async () => {
    const gate = new Gate(registryWith(new PostPolicy()), {}, contextWith(undefined));
    expect(await gate.scope(Post)).toEqual(scopeNone);
  });

  it('no policy registered for the entity → deny-all', async () => {
    const gate = new Gate(registryWith(), {});
    expect(await gate.forUser({ id: 1 }).scope(Post)).toEqual(scopeNone);
  });

  it('a policy without a scope or viewAny method → deny-all', async () => {
    @Policy(Post)
    class NoScopePolicy {
      update() {
        return true;
      }
    }
    const gate = new Gate(registryWith(new NoScopePolicy()), {});
    expect(await gate.forUser({ id: 1 }).scope(Post)).toEqual(scopeNone);
  });

  it('a viewAny-style fallback is honored when no scope method exists', async () => {
    @Policy(Post)
    class ViewAnyPolicy {
      viewAny(user: Author): ScopeConstraint {
        return eq('orgId', user.id);
      }
    }
    const gate = new Gate(registryWith(new ViewAnyPolicy()), {});
    expect(await gate.forUser({ id: 5 }).scope(Post)).toEqual(eq('orgId', 5));
  });

  it('permission-provider grant → allow-all', async () => {
    const provider: PermissionProvider = {
      hasPermission: () => false,
      getPermissions: () => ['posts.*'],
    };
    const gate = new Gate(registryWith(new PostPolicy()), {}, undefined, undefined, provider);
    // 'posts.viewAny' is satisfied by the granted 'posts.*' → allow-all.
    const c = await gate.forUser({ id: 1 }).scope(Post, 'posts.viewAny');
    expect(c).toEqual(scopeAll);
  });

  it('a scope returning false denies all', async () => {
    @Policy(Post)
    class DenyPolicy {
      scope(): false {
        return false;
      }
    }
    const gate = new Gate(registryWith(new DenyPolicy()), {});
    expect(await gate.forUser({ id: 1 }).scope(Post)).toEqual(scopeNone);
  });
});
