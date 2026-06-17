import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { beforeEach, describe, expect, it } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { AmbiguousAbilityException } from '../src/errors/exceptions.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import type { AuthzModuleOptions } from '../src/types.js';

class Post {
  constructor(
    public id: number,
    public authorId: number,
    public published = false,
  ) {}
}

@Policy(Post)
class PostPolicy {
  view(user: { id: number }, post: Post) {
    return post.published || post.authorId === user.id;
  }
  update(user: { id: number }, post: Post) {
    return post.authorId === user.id;
  }
  create(user: { id: number; verified?: boolean }) {
    return Boolean(user.verified);
  }
}

function makeGate(options: AuthzModuleOptions = {}): { gate: Gate; registry: PolicyRegistry } {
  const registry = new PolicyRegistry();
  registry.register(new PostPolicy());
  const gate = new Gate(registry, options, undefined);
  return { gate, registry };
}

describe('policy method dispatch', () => {
  let gate: Gate;
  beforeEach(() => {
    gate = makeGate().gate;
  });

  it('update allows the author', async () => {
    const author = { id: 1 };
    const post = new Post(10, 1);
    expect(await gate.forUser(author).allows('update', post)).toBe(true);
  });

  it('update denies non-authors', async () => {
    const stranger = { id: 2 };
    const post = new Post(10, 1);
    expect(await gate.forUser(stranger).allows('update', post)).toBe(false);
    expect(await gate.forUser(stranger).denies('update', post)).toBe(true);
  });

  it('view allows on published regardless of author', async () => {
    const stranger = { id: 99 };
    const post = new Post(10, 1, true);
    expect(await gate.forUser(stranger).allows('view', post)).toBe(true);
  });

  it('class-level ability (create) works without an instance', async () => {
    expect(await gate.forUser({ id: 1, verified: true }).allows('create')).toBe(true);
    expect(await gate.forUser({ id: 1, verified: false }).allows('create')).toBe(false);
  });

  it('authorize throws ForbiddenException on deny', async () => {
    const stranger = { id: 2 };
    const post = new Post(10, 1);
    await expect(gate.forUser(stranger).authorize('update', post)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('authorize resolves silently on allow', async () => {
    const author = { id: 1 };
    const post = new Post(10, 1);
    await expect(gate.forUser(author).authorize('update', post)).resolves.toBeUndefined();
  });
});

describe('PolicyRegistry.classAbilities — only resource-free (arity <= 1) methods', () => {
  it('shares class-level abilities and excludes instance methods (arity >= 2)', () => {
    const { registry } = makeGate();
    const [{ resource, abilities }] = registry.classAbilities();
    expect(resource).toBe(Post);
    // create(user) is class-level; update(user, post) / view(user, post) are not.
    expect(abilities).toContain('create');
    expect(abilities).not.toContain('update');
    expect(abilities).not.toContain('view');
  });
});

// --- P6: class-level ability with no resource must not silently pick a policy by Map order ---

describe('class-level ability resolution (no resource)', () => {
  class Comment {
    constructor(public authorId: number) {}
  }

  @Policy(Post)
  class PostPolicyB {
    create(user: { id: number }) {
      return user.id === 1;
    }
  }

  @Policy(Comment)
  class CommentPolicy {
    create(user: { id: number }) {
      return user.id === 2;
    }
  }

  it('throws AmbiguousAbilityException when >1 policy defines the method and no resource is given', async () => {
    const registry = new PolicyRegistry();
    registry.register(new PostPolicyB());
    registry.register(new CommentPolicy());
    const gate = new Gate(registry, {}, undefined);

    await expect(gate.forUser({ id: 1 }).allows('create')).rejects.toBeInstanceOf(
      AmbiguousAbilityException,
    );
  });

  it('passing the resource class disambiguates (no throw, correct policy runs)', async () => {
    const registry = new PolicyRegistry();
    registry.register(new PostPolicyB());
    registry.register(new CommentPolicy());
    const gate = new Gate(registry, {}, undefined);

    expect(await gate.forUser({ id: 1 }).allows('create', Post)).toBe(true);
    expect(await gate.forUser({ id: 1 }).allows('create', Comment)).toBe(false);
    expect(await gate.forUser({ id: 2 }).allows('create', Comment)).toBe(true);
  });

  it('a single defining policy still resolves without a resource', async () => {
    const registry = new PolicyRegistry();
    registry.register(new PostPolicyB());
    const gate = new Gate(registry, {}, undefined);

    expect(await gate.forUser({ id: 1 }).allows('create')).toBe(true);
  });
});
