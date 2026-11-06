import 'reflect-metadata';
import { AuthorizationError, Policy } from '@nestjs/authorization';
import { describe, expect, it } from 'vitest';
import {
  AbilityNotResolvedException,
  AmbiguousAbilityException,
} from '../src/errors/exceptions.js';
import { PolicyFor } from '../src/links.js';
import { AuthzPolicy } from '../src/policies/authz-policy.js';
import { RolePolicy } from '../src/policies/role.policy.js';
import { eq, scopeAll, scopeNone } from '../src/scope.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';
import { bootContext, permissionTable, roleTable } from './support/app.js';

interface User {
  id: number;
  root?: boolean;
  roles?: string[];
}

class Post {
  constructor(
    public id: number,
    public authorId: number,
  ) {}
}

@PolicyFor(Post)
class PostPolicy extends AuthzPolicy {
  update(user: User | null, post: Post) {
    return post.authorId === user?.id;
  }
  create(user: User | null) {
    return user?.id === 1;
  }
  scope(user: User) {
    return eq('authorId', user.id);
  }
}

class Doc {}

@Policy()
@PolicyFor(Doc)
class DocPolicy {
  before(user: User | null) {
    if (user?.id === 99) return false;
    return undefined;
  }
  create(user: User | null) {
    return user !== null;
  }
  viewAny(user: User) {
    return user.id === 1;
  }
}

/** Not linked to a resource: reached only by naming it. */
@Policy()
class ReportPolicy {
  export(user: User | null, format: string) {
    return user?.id === 1 && format === 'csv';
  }
}

const root: User = { id: 42, root: true };

async function gateWith(extra: Parameters<typeof bootContext>[0] = {}) {
  return bootContext({
    providers: [PostPolicy, DocPolicy, ReportPolicy],
    authz: { superAdmin: (u) => (u as User | null)?.root === true },
    ...extra,
  });
}

describe('Gate', () => {
  it('string abilities run the policy linked to the resource, through the official service', async () => {
    const { gate } = await gateWith();
    expect(await gate.forUser({ id: 1 }).allows('update', new Post(1, 1))).toBe(true);
    expect(await gate.forUser({ id: 2 }).allows('update', new Post(1, 1))).toBe(false);
    expect(await gate.forUser({ id: 2 }).denies('update', new Post(1, 1))).toBe(true);
  });

  it('names an official policy directly, exactly like AuthorizationService.can()', async () => {
    const { gate } = await gateWith();
    expect(await gate.forUser({ id: 1 }).allows(ReportPolicy, 'export', 'csv')).toBe(true);
    expect(await gate.forUser({ id: 1 }).allows(ReportPolicy, 'export', 'pdf')).toBe(false);
  });

  it('a class-level ability by resource class, or unambiguous by name', async () => {
    const { gate } = await gateWith();
    expect(await gate.forUser({ id: 1 }).allows('create', Post)).toBe(true);
    expect(await gate.forUser({ id: 2 }).allows('create', Post)).toBe(false);
    await expect(gate.forUser({ id: 1 }).allows('create')).rejects.toBeInstanceOf(
      AmbiguousAbilityException,
    );
  });

  it('runs the policy before() hook (the official evaluator)', async () => {
    const { gate } = await gateWith();
    expect(await gate.forUser({ id: 5 }).allows('create', Doc)).toBe(true);
    expect(await gate.forUser({ id: 99 }).allows('create', Doc)).toBe(false);
  });

  it('superAdmin grants string abilities and AuthzPolicy subclasses', async () => {
    const { gate } = await gateWith();
    expect(await gate.forUser(root).allows('update', new Post(1, 1))).toBe(true);
    expect(await gate.forUser(root).allows(PostPolicy, 'update', new Post(1, 1))).toBe(true);
    // ReportPolicy does not extend AuthzPolicy.
    expect(await gate.forUser(root).allows(ReportPolicy, 'export', 'csv')).toBe(false);
  });

  it('ad-hoc gates: guests are denied, unknown abilities throw', async () => {
    const { gate } = await gateWith();
    gate.define('access-admin', (u) => (u as User).id === 1);
    expect(gate.hasGate('access-admin')).toBe(true);
    expect(gate.gateNames()).toEqual(['access-admin']);
    expect(await gate.forUser({ id: 1 }).allows('access-admin')).toBe(true);
    expect(await gate.forUser(null).allows('access-admin')).toBe(false);
    await expect(gate.forUser({ id: 1 }).allows('nope')).rejects.toBeInstanceOf(
      AbilityNotResolvedException,
    );
  });

  it('named permissions grant string abilities (wildcards apply)', async () => {
    const { provider } = permissionTable({ '1': ['posts.*'] });
    const { gate } = await gateWith({ permissions: provider });
    expect(await gate.forUser({ id: 1 }).allows('posts.publish')).toBe(true);
    await expect(gate.forUser({ id: 2 }).allows('posts.publish')).rejects.toBeInstanceOf(
      AbilityNotResolvedException,
    );
  });

  it('the policy has the final word: a permission named like its ability does not bypass it', async () => {
    const { provider, calls } = permissionTable({ '2': ['update', 'create', '*'] });
    const { gate } = await gateWith({ permissions: provider });
    // User 2 holds `update` (and `*`), but PostPolicy.update denies a post they do not own.
    expect(await gate.forUser({ id: 2 }).allows('update', new Post(1, 1))).toBe(false);
    expect(await gate.forUser({ id: 2 }).allows('create', Post)).toBe(false);
    expect(await gate.forUser({ id: 2 }).allows(PostPolicy, 'update', new Post(1, 1))).toBe(false);
    expect(
      (
        await gate.forUser({ id: 2 }).allowsMany([{ ability: 'update', resource: new Post(1, 1) }])
      )[0]?.allowed,
    ).toBe(false);
    // The permissions are not even fetched for an ability a policy defines…
    expect(calls.getPermissions).toBe(0);
    // …they still grant named abilities no policy defines,
    expect(await gate.forUser({ id: 2 }).allows('posts.publish')).toBe(true);
    // and super-admin still short-circuits the policy.
    expect(await gate.forUser(root).allows('update', new Post(1, 1))).toBe(true);
  });

  it('authorize() throws the official AuthorizationError (401 for guests, 403 otherwise)', async () => {
    const { gate } = await gateWith();
    await gate.forUser({ id: 1 }).authorize('update', new Post(1, 1));
    const forbidden = await gate
      .forUser({ id: 2 })
      .authorize('update', new Post(1, 1))
      .catch((e) => e);
    expect(forbidden).toBeInstanceOf(AuthorizationError);
    expect(forbidden).toMatchObject({ status: 403, policy: 'PostPolicy', ability: 'update' });
    const guest = await gate
      .forUser(undefined)
      .authorize(ReportPolicy, 'export', 'csv')
      .catch((e) => e);
    expect(guest).toMatchObject({ status: 401, reason: 'unauthenticated' });
  });

  it('allowsMany keeps order, isolates failures and fetches permissions once', async () => {
    const { provider, calls } = permissionTable({ '1': ['posts.publish', 'posts.archive'] });
    const { gate } = await gateWith({ permissions: provider });
    const results = await gate
      .forUser({ id: 1 })
      .allowsMany([
        { ability: 'posts.publish' },
        { ability: 'posts.archive' },
        { ability: 'update', resource: new Post(1, 2) },
        { ability: 'nope' },
        { policy: ReportPolicy, ability: 'export', args: ['csv'] },
      ]);
    expect(results.map((r) => r.allowed)).toEqual([true, true, false, false, true]);
    expect(calls.getPermissions).toBe(1);
  });

  it('roles: a fact about the user (superAdmin does not apply)', async () => {
    const { gate } = await gateWith({ roles: roleTable({ '3': ['editor'] }) });
    expect(await gate.forUser({ id: 3 }).hasRole('editor')).toBe(true);
    expect(await gate.forUser({ id: 1, roles: ['admin'] }).hasAnyRole(['editor', 'admin'])).toBe(
      true,
    );
    expect(await gate.forUser(root).hasRole('editor')).toBe(false);
    expect(await gate.forUser(root).allows(RolePolicy, 'has', 'editor')).toBe(true);
  });

  it('uses the nestjs-context user when none is passed, hydrated by resolveUser', async () => {
    const store = {};
    const { gate } = await gateWith({
      providers: [
        PostPolicy,
        DocPolicy,
        ReportPolicy,
        {
          provide: CONTEXT_ACCESSOR,
          useValue: {
            traceId: () => undefined,
            tenantId: () => undefined,
            userRef: () => ({ type: 'User', id: 1 }),
            get: () => store,
          },
        },
      ],
      authz: { resolveUser: (ref) => ({ id: Number(ref.id) }) },
    });
    expect(await gate.allows('update', new Post(1, 1))).toBe(true);
    expect(await gate.allows(ReportPolicy, 'export', 'csv')).toBe(true);
  });

  it('a guest without a context is null to the policy', async () => {
    const { gate } = await gateWith();
    expect(await gate.allows('create', Doc)).toBe(false);
  });

  it('checks what an overrideProvider() test replacement answers', async () => {
    const { Test } = await import('@nestjs/testing');
    const { AuthorizationModule } = await import('@nestjs/authorization');
    const { AuthzModule } = await import('../src/module.js');
    const { Gate } = await import('../src/gate.js');
    const mod = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot(), AuthzModule.forRoot()],
      providers: [PostPolicy],
    })
      .overrideProvider(PostPolicy)
      .useValue({ update: () => true })
      .compile();
    await mod.init();
    expect(await mod.get(Gate).forUser({ id: 2 }).allows('update', new Post(1, 1))).toBe(true);
  });

  describe('scope', () => {
    it('the policy scope() for the user', async () => {
      const { gate } = await gateWith();
      expect(await gate.forUser({ id: 7 }).scope(Post)).toEqual(eq('authorId', 7));
      expect(await gate.forUser({ id: 7 }).scope(PostPolicy)).toEqual(eq('authorId', 7));
    });

    it('terminal verdicts: superAdmin, guest, before(), no policy', async () => {
      const { provider } = permissionTable({ '5': ['viewAny'] });
      const { gate } = await gateWith({ permissions: provider });
      expect(await gate.forUser(root).scope(Post)).toEqual(scopeAll);
      // The policy has the final word: a `viewAny` permission does not widen its scope.
      expect(await gate.forUser({ id: 5 }).scope(Post)).toEqual(eq('authorId', 5));
      expect(await gate.forUser(null).scope(Post)).toEqual(scopeNone);
      expect(await gate.forUser({ id: 99 }).scope(Doc)).toEqual(scopeNone);
      expect(await gate.forUser({ id: 1 }).scope(Doc)).toEqual(scopeAll); // viewAny fallback
      expect(await gate.forUser({ id: 2 }).scope(Doc)).toEqual(scopeNone);
      class Unlinked {}
      expect(await gate.forUser({ id: 1 }).scope(Unlinked)).toEqual(scopeNone);
      // Without a policy to ask, a persisted permission scopes the entity.
      expect(await gate.forUser({ id: 5 }).scope(Unlinked)).toEqual(scopeAll);
    });
  });
});
