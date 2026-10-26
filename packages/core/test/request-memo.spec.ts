import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ContextAccessor, ContextStore, UserRef } from '../src/context-accessor.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { PermissionCache } from '../src/permission-cache.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import type { RoleProvider } from '../src/role-provider.js';

/** One request: a context accessor over a single store object. */
function requestContext(ref: UserRef | undefined): ContextAccessor {
  const store: ContextStore = {};
  return {
    traceId: () => undefined,
    tenantId: () => undefined,
    userRef: () => ref,
    get: () => store,
  };
}

class Post {
  constructor(
    public id: number,
    public authorId: number,
  ) {}
}

@Policy(Post)
class PostPolicy {
  view(user: { id: number }, post: Post) {
    return post.authorId === user.id;
  }
  update(user: { id: number }, post: Post) {
    return post.authorId === user.id;
  }
}

function registry(): PolicyRegistry {
  const r = new PolicyRegistry();
  r.register(new PostPolicy());
  return r;
}

const posts = Array.from({ length: 50 }, (_, i) => new Post(i, i % 2 === 0 ? 1 : 2));

describe('per-request memoization', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('an exhaustive provider answers a 50-row list from one fetch, never calling hasPermission', async () => {
    const hasPermission = vi.fn(() => false);
    const getPermissions = vi.fn(() => ['reports.view']);
    const provider: PermissionProvider = {
      hasPermission,
      getPermissions,
      exhaustivePermissions: true,
    };
    const gate = new Gate(
      registry(),
      {},
      requestContext({ type: 'user', id: 1 }),
      undefined,
      provider,
    );
    const user = gate.forUser({ id: 1 });

    for (const post of posts) {
      expect(await user.allows('view', post)).toBe(post.authorId === 1);
      expect(await user.allows('update', post)).toBe(post.authorId === 1);
    }

    expect(getPermissions).toHaveBeenCalledTimes(1);
    expect(hasPermission).not.toHaveBeenCalled();
  });

  it('a provider that does not declare its set exhaustive still gets hasPermission on a miss', async () => {
    const hasPermission = vi.fn(
      (_u: unknown, _p: string, resource?: unknown) =>
        resource instanceof Post && resource.id === 3,
    );
    const provider: PermissionProvider = {
      hasPermission,
      getPermissions: () => ['reports.view'],
    };
    const gate = new Gate(
      registry(),
      {},
      requestContext({ type: 'user', id: 9 }),
      undefined,
      provider,
    );
    const user = gate.forUser({ id: 9 });

    expect(await user.allows('update', posts[3])).toBe(true);
    expect(await user.allows('update', posts[4])).toBe(false);
    expect(hasPermission).toHaveBeenCalledTimes(2);
  });

  it('runs resolveUser once per request, however many checks run', async () => {
    const resolveUser = vi.fn(async (ref: UserRef) => ({ id: ref.id }));
    const gate = new Gate(registry(), { resolveUser }, requestContext({ type: 'user', id: 1 }));

    for (const post of posts) await gate.allows('view', post);
    await gate.authorize('update', posts[0]);
    await gate.hasRole('editor');

    expect(resolveUser).toHaveBeenCalledTimes(1);
  });

  it('keys the permission cache by type:id, so re-hydrated copies of one user share a fetch', async () => {
    const getPermissions = vi.fn(() => ['posts.*']);
    const provider: PermissionProvider = { hasPermission: () => false, getPermissions };
    const gate = new Gate(new PolicyRegistry(), {}, requestContext(undefined), undefined, provider);

    // Distinct objects for the same row, as an ORM without an identity map returns them.
    for (let i = 0; i < 10; i++) {
      expect(await gate.forUser({ type: 'user', id: 7 }).allows('posts.update')).toBe(true);
    }
    expect(getPermissions).toHaveBeenCalledTimes(1);
  });

  it('keeps different users (and different classes sharing an id) apart', async () => {
    class Admin {
      constructor(public id: number) {}
    }
    class Member {
      constructor(public id: number) {}
    }
    const getPermissions = vi.fn((user: unknown) => (user instanceof Admin ? ['*'] : []));
    const provider: PermissionProvider = {
      hasPermission: () => false,
      getPermissions,
      exhaustivePermissions: true,
    };
    const gate = new Gate(new PolicyRegistry(), {}, requestContext(undefined), undefined, provider);
    gate.define('posts.update', () => false);

    expect(await gate.forUser(new Admin(1)).allows('posts.update')).toBe(true);
    expect(await gate.forUser(new Member(1)).allows('posts.update')).toBe(false);
    expect(await gate.forUser({ id: 2 }).allows('posts.update')).toBe(false);
    expect(getPermissions).toHaveBeenCalledTimes(3);
  });

  it('fetches provider roles once per request across hasRole / hasAnyRole', async () => {
    const getRoles = vi.fn(() => ['editor']);
    const roleProvider: RoleProvider = { getRoles };
    const gate = new Gate(
      new PolicyRegistry(),
      {},
      requestContext({ type: 'user', id: 1 }),
      undefined,
      undefined,
      roleProvider,
    );

    expect(await gate.hasRole('editor')).toBe(true);
    expect(await gate.hasRole('admin')).toBe(false);
    expect(await gate.hasAnyRole(['admin', 'editor'])).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 1 }).hasRole('editor')).toBe(true);

    expect(getRoles).toHaveBeenCalledTimes(1);
  });

  it('roles read off the user object are never served from the cache', async () => {
    const gate = new Gate(new PolicyRegistry(), {}, requestContext(undefined));
    expect(await gate.forUser({ id: 1, roles: ['a'] }).hasRole('a')).toBe(true);
    expect(await gate.forUser({ id: 1, roles: ['b'] }).hasRole('b')).toBe(true);
  });

  it('does not re-split exact grants on every check', async () => {
    const granted = Array.from({ length: 200 }, (_, i) => `module${i % 20}.resource${i}.action`);
    const provider: PermissionProvider = {
      hasPermission: () => false,
      getPermissions: () => granted,
    };
    const cache = new PermissionCache();
    const user = { id: 1 };
    await cache.satisfies(provider, user, 'warm.up');

    const split = vi.spyOn(String.prototype, 'split');
    for (let i = 0; i < 100; i++) {
      expect(await cache.satisfies(provider, user, 'posts.update')).toBe(false);
    }
    // 200 grants x 100 checks would be 40k splits if every grant were re-matched.
    expect(split.mock.calls.length).toBeLessThan(100);
  });
});
