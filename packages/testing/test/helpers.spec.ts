import 'reflect-metadata';
import { Policy } from '@dudousxd/nestjs-authz';
import { describe, expect, it } from 'vitest';
import {
  AuthzAssertionError,
  FakePermissionProvider,
  FakeRoleProvider,
  buildBoundGate,
  buildGate,
  expectCan,
  expectCannot,
} from '../src/index.js';

class Post {
  constructor(
    readonly id: number,
    readonly authorId: number,
  ) {}
}

@Policy(Post)
class PostPolicy {
  before(user: { isAdmin?: boolean } | undefined) {
    if (user?.isAdmin) return true;
  }
  view(_user: unknown, post: Post) {
    return post.authorId === 1;
  }
  update(user: { id: number } | undefined, post: Post) {
    return user?.id === post.authorId;
  }
  create(user: { id: number } | undefined) {
    return user !== undefined;
  }
}

describe('buildGate + expectCan/expectCannot', () => {
  it('builds a Gate that dispatches a registered @Policy', async () => {
    const gate = buildGate({ policies: [new PostPolicy()] });
    await expectCan(gate, { id: 1 }, 'update', new Post(10, 1));
    await expectCannot(gate, { id: 2 }, 'update', new Post(10, 1));
  });

  it('honors the policy before-hook (admin bypass)', async () => {
    const gate = buildGate({ policies: [new PostPolicy()] });
    await expectCan(gate, { id: 99, isAdmin: true }, 'update', new Post(10, 1));
  });

  it('resolves class-level abilities (no resource)', async () => {
    const gate = buildGate({ policies: [new PostPolicy()] });
    await expectCan(gate, { id: 5 }, 'create', Post);
  });

  it('registers ad-hoc gates from the `gates` fixture', async () => {
    const gate = buildGate({
      gates: { 'access-admin': (u) => (u as { staff?: boolean }).staff === true },
    });
    await expectCan(gate, { staff: true }, 'access-admin');
    await expectCannot(gate, { staff: false }, 'access-admin');
  });

  it('applies the global superAdmin hook', async () => {
    const gate = buildGate({
      policies: [new PostPolicy()],
      superAdmin: (u) => (u as { root?: boolean }).root === true,
    });
    await expectCan(gate, { id: 123, root: true }, 'update', new Post(1, 1));
  });

  it('expectCannot treats an unresolved ability as "cannot" (no throw)', async () => {
    const gate = buildGate();
    await expectCannot(gate, { id: 1 }, 'totally.unknown.ability');
  });

  it('expectCan throws AuthzAssertionError with a helpful message on a deny', async () => {
    const gate = buildGate({ policies: [new PostPolicy()] });
    await expect(expectCan(gate, { id: 2 }, 'update', new Post(10, 1))).rejects.toBeInstanceOf(
      AuthzAssertionError,
    );
    await expect(expectCan(gate, { id: 2 }, 'update', new Post(10, 1))).rejects.toThrow(/update/);
  });

  it('expectCannot throws when the ability is actually ALLOWED', async () => {
    const gate = buildGate({ policies: [new PostPolicy()] });
    await expect(expectCannot(gate, { id: 1 }, 'update', new Post(10, 1))).rejects.toBeInstanceOf(
      AuthzAssertionError,
    );
  });
});

describe('buildBoundGate', () => {
  it('binds a fixture user and accepts undefined user in assertions', async () => {
    const bound = buildBoundGate({ id: 1 }, { policies: [new PostPolicy()] });
    await expectCan(bound, undefined, 'update', new Post(10, 1));
    await expectCannot(bound, undefined, 'view', new Post(10, 2)); // authorId !== 1
  });
});

describe('FakePermissionProvider', () => {
  it('grants exact + wildcard permissions through the Gate seam', async () => {
    const provider = new FakePermissionProvider({ '1': ['posts.*'], '2': ['posts.read'] });
    const gate = buildGate({ permissionProvider: provider });

    await expectCan(gate, { id: 1 }, 'posts.update'); // wildcard
    await expectCan(gate, { id: 2 }, 'posts.read'); // exact
    await expectCannot(gate, { id: 2 }, 'posts.update'); // not granted
  });

  it('supports chainable grant()', async () => {
    const provider = new FakePermissionProvider();
    provider.grant({ id: 7 }, 'reports.export');
    const gate = buildGate({ permissionProvider: provider });
    await expectCan(gate, { id: 7 }, 'reports.export');
    await expectCannot(gate, { id: 8 }, 'reports.export');
  });
});

describe('FakeRoleProvider', () => {
  it('answers coarse role checks via the Gate', async () => {
    const provider = new FakeRoleProvider({ '1': ['editor', 'admin'] });
    const gate = buildGate({ roleProvider: provider });

    expect(await gate.forUser({ id: 1 }).hasRole('editor')).toBe(true);
    expect(await gate.forUser({ id: 1 }).hasAnyRole(['nope', 'admin'])).toBe(true);
    expect(await gate.forUser({ id: 2 }).hasRole('editor')).toBe(false);
  });
});
