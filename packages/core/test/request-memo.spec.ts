import 'reflect-metadata';
import { AsyncLocalStorage } from 'node:async_hooks';
import { AuthorizationModule, Can, Policy } from '@nestjs/authorization';
import { Controller, Get, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ContextAccessor, ContextStore, UserRef } from '../src/context-accessor.js';
import { Gate } from '../src/gate.js';
import { permission, roles } from '../src/helpers.js';
import { PolicyFor } from '../src/links.js';
import { AuthzModule } from '../src/module.js';
import { PermissionCache } from '../src/permission-cache.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { PermissionPolicy } from '../src/policies/permission.policy.js';
import { RolePolicy } from '../src/policies/role.policy.js';
import type { RoleProvider } from '../src/role-provider.js';
import { CONTEXT_ACCESSOR, PERMISSION_PROVIDER, ROLE_PROVIDER } from '../src/tokens.js';
import type { AuthzModuleOptions } from '../src/types.js';
import { asUser, bootContext, userFromHeader } from './support/app.js';

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

@Policy()
@PolicyFor(Post)
class PostPolicy {
  view(user: { id: number } | null, post: Post) {
    return post.authorId === user?.id;
  }
  update(user: { id: number } | null, post: Post) {
    return post.authorId === user?.id;
  }
}

interface MemoOptions {
  ref?: UserRef;
  permissions?: PermissionProvider;
  roles?: RoleProvider;
  authz?: AuthzModuleOptions;
}

/** A Gate inside one "request": a nestjs-context accessor over a single store. */
async function gateFor(options: MemoOptions = {}): Promise<Gate> {
  const { gate } = await bootContext({
    providers: [PostPolicy, { provide: CONTEXT_ACCESSOR, useValue: requestContext(options.ref) }],
    ...(options.permissions ? { permissions: options.permissions } : {}),
    ...(options.roles ? { roles: options.roles } : {}),
    ...(options.authz ? { authz: options.authz } : {}),
  });
  return gate;
}

const posts = Array.from({ length: 50 }, (_, i) => new Post(i, i % 2 === 0 ? 1 : 2));

describe('per-request memoization', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('an exhaustive provider answers a 50-row list from one fetch, never calling hasPermission', async () => {
    const hasPermission = vi.fn(() => false);
    const getPermissions = vi.fn(() => ['reports.view']);
    const gate = await gateFor({
      ref: { type: 'user', id: 1 },
      permissions: { hasPermission, getPermissions, exhaustivePermissions: true },
    });
    gate.define('posts.delete', () => false);
    const user = gate.forUser({ id: 1 });

    for (const post of posts) {
      expect(await user.allows('reports.view', post)).toBe(true);
      expect(await user.allows('posts.delete', post)).toBe(false);
      // The linked policy decides its own abilities, without a permission fetch.
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
    const gate = await gateFor({
      ref: { type: 'user', id: 9 },
      permissions: { hasPermission, getPermissions: () => ['reports.view'] },
    });
    gate.define('posts.archive', () => false);
    const user = gate.forUser({ id: 9 });

    expect(await user.allows('posts.archive', posts[3])).toBe(true);
    expect(await user.allows('posts.archive', posts[4])).toBe(false);
    expect(hasPermission).toHaveBeenCalledTimes(2);
  });

  it('runs resolveUser once per request, however many checks run', async () => {
    const resolveUser = vi.fn(async (ref: UserRef) => ({ id: ref.id }));
    const gate = await gateFor({ ref: { type: 'user', id: 1 }, authz: { resolveUser } });

    for (const post of posts) await gate.allows('view', post);
    await gate.authorize('update', posts[0] as Post);
    await gate.hasRole('editor');

    expect(resolveUser).toHaveBeenCalledTimes(1);
  });

  it('keys the permission cache by type:id, so re-hydrated copies of one user share a fetch', async () => {
    const getPermissions = vi.fn(() => ['posts.*']);
    const gate = await gateFor({ permissions: { hasPermission: () => false, getPermissions } });

    // Distinct objects for the same row, as an ORM without an identity map returns them.
    for (let i = 0; i < 10; i++) {
      expect(await gate.forUser({ type: 'user', id: 7 }).allows('posts.publish')).toBe(true);
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
    const gate = await gateFor({
      permissions: { hasPermission: () => false, getPermissions, exhaustivePermissions: true },
    });
    gate.define('posts.publish', () => false);

    expect(await gate.forUser(new Admin(1)).allows('posts.publish')).toBe(true);
    expect(await gate.forUser(new Member(1)).allows('posts.publish')).toBe(false);
    expect(await gate.forUser({ id: 2 }).allows('posts.publish')).toBe(false);
    expect(getPermissions).toHaveBeenCalledTimes(3);
  });

  it('keeps plain-object users without a type apart even when their ids match', async () => {
    const getPermissions = vi.fn((user: unknown) =>
      (user as { kind: string }).kind === 'service' ? ['*'] : [],
    );
    const getRoles = vi.fn((user: unknown) =>
      (user as { kind: string }).kind === 'service' ? ['robot'] : [],
    );
    const gate = await gateFor({
      permissions: { hasPermission: () => false, getPermissions, exhaustivePermissions: true },
      roles: { getRoles },
    });
    gate.define('posts.publish', () => false);
    const human = { id: 1, kind: 'human' };
    const service = { id: 1, kind: 'service' };

    expect(await gate.forUser(service).allows('posts.publish')).toBe(true);
    expect(await gate.forUser(human).allows('posts.publish')).toBe(false);
    expect(await gate.forUser(service).hasRole('robot')).toBe(true);
    expect(await gate.forUser(human).hasRole('robot')).toBe(false);
  });

  it('re-loaded entity instances of one class share an entry', async () => {
    class Account {
      constructor(public id: number) {}
    }
    const getPermissions = vi.fn(() => ['posts.*']);
    const gate = await gateFor({ permissions: { hasPermission: () => false, getPermissions } });

    for (let i = 0; i < 5; i++) {
      expect(await gate.forUser(new Account(3)).allows('posts.publish')).toBe(true);
    }
    expect(getPermissions).toHaveBeenCalledTimes(1);
  });

  it('two classes that share a name never share an entry', async () => {
    const make = () =>
      class User {
        constructor(public id: number) {}
      };
    const A = make();
    const B = make();
    const getPermissions = vi.fn((user: unknown) => (user instanceof A ? ['*'] : []));
    const gate = await gateFor({
      permissions: { hasPermission: () => false, getPermissions, exhaustivePermissions: true },
    });
    gate.define('posts.publish', () => false);

    expect(await gate.forUser(new A(1)).allows('posts.publish')).toBe(true);
    expect(await gate.forUser(new B(1)).allows('posts.publish')).toBe(false);
  });

  it('fetches provider roles once per request across hasRole / hasAnyRole', async () => {
    const getRoles = vi.fn(() => ['editor']);
    const gate = await gateFor({ ref: { type: 'user', id: 1 }, roles: { getRoles } });

    expect(await gate.hasRole('editor')).toBe(true);
    expect(await gate.hasRole('admin')).toBe(false);
    expect(await gate.hasAnyRole(['admin', 'editor'])).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 1 }).hasRole('editor')).toBe(true);

    expect(getRoles).toHaveBeenCalledTimes(1);
  });

  it('roles read off the user object are never served from the cache', async () => {
    const gate = await gateFor();
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

describe('per-request memoization on routes', () => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('the official guard (RolePolicy, PermissionPolicy) and the handler share one fetch per request', async () => {
    // nestjs-context's role: one store per request, opened before the guards run.
    const als = new AsyncLocalStorage<ContextStore>();
    const accessor: ContextAccessor = {
      traceId: () => undefined,
      tenantId: () => undefined,
      userRef: () => undefined,
      get: () => als.getStore() as ContextStore,
    };
    const getPermissions = vi.fn(() => ['posts.*']);
    const getRoles = vi.fn(() => ['editor']);

    @Controller('posts')
    class PostController {
      constructor(private readonly gate: Gate) {}

      @Get('publish')
      @Can(RolePolicy, 'has', roles('editor'))
      @Can(PermissionPolicy, 'has', permission('posts.publish'))
      @Can(PermissionPolicy, 'hasAll', permission('posts.update', 'posts.delete'))
      async publish() {
        const user = this.gate.forUser({ type: 'user', id: 1 });
        return {
          many: (
            await user.allowsMany([{ ability: 'posts.archive' }, { ability: 'posts.restore' }])
          ).map((r) => r.allowed),
          editor: await user.hasRole('editor'),
        };
      }
    }

    const mod = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot({ getUser: userFromHeader }), AuthzModule.forRoot()],
      controllers: [PostController],
      providers: [
        { provide: CONTEXT_ACCESSOR, useValue: accessor },
        {
          provide: PERMISSION_PROVIDER,
          useValue: { hasPermission: () => false, getPermissions, exhaustivePermissions: true },
        },
        { provide: ROLE_PROVIDER, useValue: { getRoles } },
      ],
    }).compile();
    app = mod.createNestApplication({ logger: false });
    app.use((_req: unknown, _res: unknown, next: () => void) => als.run({}, next));
    await app.init();

    for (let i = 0; i < 2; i++) {
      const res = await request(app.getHttpServer())
        .get('/posts/publish')
        .set(asUser({ type: 'user', id: 1 }))
        .expect(200);
      expect(res.body).toEqual({ many: [true, true], editor: true });
    }
    // Once per request (two requests), not once per check: the guard's user and the
    // handler's copy name the same row (`type` + `id`), so they share the entry.
    expect(getPermissions).toHaveBeenCalledTimes(2);
    expect(getRoles).toHaveBeenCalledTimes(2);
  });
});
