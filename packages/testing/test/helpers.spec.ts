import 'reflect-metadata';
import { PermissionPolicy, PolicyFor, Roles, byId, permission } from '@dudousxd/nestjs-authz';
import { Can } from '@nestjs/authorization';
import { describe, expect, it } from 'vitest';
import {
  AuthzAssertionError,
  FakePermissionProvider,
  FakeRoleProvider,
  buildBoundGate,
  buildGate,
  expectCan,
  expectCannot,
  requirementsOf,
} from '../src/index.js';

class Post {
  constructor(
    readonly id: number,
    readonly authorId: number,
  ) {}
}

@PolicyFor(Post)
class PostPolicy {
  before(user: { isAdmin?: boolean } | null) {
    if (user?.isAdmin) return true;
    return undefined;
  }
  view(_user: unknown, post: Post) {
    return post.authorId === 1;
  }
  update(user: { id: number } | null, post: Post) {
    return user?.id === post.authorId;
  }
  create(user: { id: number } | null) {
    return user !== null;
  }
}

describe('buildGate + expectCan/expectCannot', () => {
  it('builds a Gate that dispatches a registered @Policy', async () => {
    const gate = await buildGate({ policies: [PostPolicy] });
    await expectCan(gate, { id: 1 }, 'update', new Post(10, 1));
    await expectCannot(gate, { id: 2 }, 'update', new Post(10, 1));
  });

  it('honors the policy before-hook (admin bypass)', async () => {
    const gate = await buildGate({ policies: [PostPolicy] });
    await expectCan(gate, { id: 99, isAdmin: true }, 'update', new Post(10, 1));
  });

  it('resolves class-level abilities (no resource)', async () => {
    const gate = await buildGate({ policies: [PostPolicy] });
    await expectCan(gate, { id: 5 }, 'create', Post);
  });

  it('registers ad-hoc gates from the `gates` fixture', async () => {
    const gate = await buildGate({
      gates: { 'access-admin': (u) => (u as { staff?: boolean }).staff === true },
    });
    await expectCan(gate, { staff: true }, 'access-admin');
    await expectCannot(gate, { staff: false }, 'access-admin');
  });

  it('applies the global superAdmin hook', async () => {
    const gate = await buildGate({
      policies: [PostPolicy],
      superAdmin: (u) => (u as { root?: boolean }).root === true,
    });
    await expectCan(gate, { id: 123, root: true }, 'update', new Post(1, 1));
  });

  it('expectCannot treats an unresolved ability as "cannot" (no throw)', async () => {
    const gate = await buildGate();
    await expectCannot(gate, { id: 1 }, 'totally.unknown.ability');
  });

  it('expectCan throws AuthzAssertionError with a helpful message on a deny', async () => {
    const gate = await buildGate({ policies: [PostPolicy] });
    await expect(expectCan(gate, { id: 2 }, 'update', new Post(10, 1))).rejects.toBeInstanceOf(
      AuthzAssertionError,
    );
    await expect(expectCan(gate, { id: 2 }, 'update', new Post(10, 1))).rejects.toThrow(/update/);
  });

  it('expectCannot throws when the ability is actually ALLOWED', async () => {
    const gate = await buildGate({ policies: [PostPolicy] });
    await expect(expectCannot(gate, { id: 1 }, 'update', new Post(10, 1))).rejects.toBeInstanceOf(
      AuthzAssertionError,
    );
  });
});

describe('buildBoundGate', () => {
  it('binds a fixture user and accepts undefined user in assertions', async () => {
    const bound = await buildBoundGate({ id: 1 }, { policies: [PostPolicy] });
    await expectCan(bound, undefined, 'update', new Post(10, 1));
    await expectCannot(bound, undefined, 'view', new Post(10, 2)); // authorId !== 1
  });
});

describe('FakePermissionProvider', () => {
  it('grants exact + wildcard permissions through the Gate seam', async () => {
    const provider = new FakePermissionProvider({ '1': ['posts.*'], '2': ['posts.read'] });
    const gate = await buildGate({ permissionProvider: provider });

    await expectCan(gate, { id: 1 }, 'posts.update'); // wildcard
    await expectCan(gate, { id: 2 }, 'posts.read'); // exact
    await expectCannot(gate, { id: 2 }, 'posts.update'); // not granted
  });

  it('supports chainable grant()', async () => {
    const provider = new FakePermissionProvider();
    provider.grant({ id: 7 }, 'reports.export');
    const gate = await buildGate({ permissionProvider: provider });
    await expectCan(gate, { id: 7 }, 'reports.export');
    await expectCannot(gate, { id: 8 }, 'reports.export');
  });
});

describe('FakeRoleProvider', () => {
  it('answers coarse role checks via the Gate', async () => {
    const provider = new FakeRoleProvider({ '1': ['editor', 'admin'] });
    const gate = await buildGate({ roleProvider: provider });

    expect(await gate.forUser({ id: 1 }).hasRole('editor')).toBe(true);
    expect(await gate.forUser({ id: 1 }).hasAnyRole(['nope', 'admin'])).toBe(true);
    expect(await gate.forUser({ id: 2 }).hasRole('editor')).toBe(false);
  });
});

describe('official-style checks and route requirements', () => {
  it('expectCan accepts an official policy class', async () => {
    const gate = await buildGate({ policies: [PostPolicy] });
    await expectCan(gate, { id: 1 }, PostPolicy, 'update', new Post(10, 1));
    await expectCannot(gate, { id: 2 }, PostPolicy, 'update', new Post(10, 1));
    await expect(expectCan(gate, { id: 2 }, PostPolicy, 'update', new Post(10, 1))).rejects.toThrow(
      /PostPolicy\.update/,
    );
  });

  it('requirementsOf lists what the official guard enforces, with static args', () => {
    @Roles('admin')
    class PostController {
      @Can(PermissionPolicy, 'has', permission('posts.publish'))
      publish() {}
      @Can(PostPolicy, 'update', byId(Post))
      update() {}
    }
    expect(requirementsOf(PostController, 'publish')).toEqual([
      expect.objectContaining({ ability: 'has', staticArgs: ['admin'], dynamic: false }),
      { policy: PermissionPolicy, ability: 'has', staticArgs: ['posts.publish'], dynamic: false },
    ]);
    expect(requirementsOf(PostController, 'update')[1]).toEqual({
      policy: PostPolicy,
      ability: 'update',
      staticArgs: undefined,
      dynamic: true,
    });
  });
});
