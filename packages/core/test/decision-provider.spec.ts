import 'reflect-metadata';
import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import { AuthorizationError, Can, Policy } from '@nestjs/authorization';
import { Controller, Patch } from '@nestjs/common';
import request from 'supertest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DecisionProvider } from '../src/decision-provider.js';
import { authzDecisionChannel } from '../src/diagnostics.js';
import { byId, permission } from '../src/helpers.js';
import { PolicyFor } from '../src/links.js';
import type { PermissionProvider } from '../src/permission-provider.js';
import { AuthzPolicy } from '../src/policies/authz-policy.js';
import { PermissionPolicy } from '../src/policies/permission.policy.js';
import { eq, scopeNone } from '../src/scope.js';
import { DECISION_PROVIDER } from '../src/tokens.js';
import type { AuthzModuleOptions } from '../src/types.js';
import { asUser, bootApp, bootContext } from './support/app.js';

class Post {
  constructor(
    readonly id: number | string,
    readonly ownerId = 1,
  ) {}
}

interface U {
  id: number;
  admin?: boolean;
}

@Policy()
@PolicyFor(Post)
class PostPolicy extends AuthzPolicy {
  update(user: U | null, post: Post) {
    return user?.id === post.ownerId;
  }
  scope(user: U) {
    return eq('ownerId', user.id);
  }
}

async function gate(
  decision: DecisionProvider | undefined,
  options: AuthzModuleOptions = {},
  permissions?: PermissionProvider,
) {
  const { gate } = await bootContext({
    providers: [
      PostPolicy,
      ...(decision ? [{ provide: DECISION_PROVIDER, useValue: decision }] : []),
    ],
    authz: options,
    ...(permissions ? { permissions } : {}),
  });
  return gate;
}

describe('DecisionProvider seam', () => {
  it('an explicit deny overrides a policy that would allow', async () => {
    const g = await gate({ decide: () => false });
    expect(await g.forUser({ id: 1 }).allows('update', new Post(1))).toBe(false);
    expect(await g.forUser({ id: 1 }).allows(PostPolicy, 'update', new Post(1))).toBe(false);
  });

  it('an explicit allow overrides a policy that would deny', async () => {
    const g = await gate({ decide: () => true });
    expect(await g.forUser({ id: 2 }).allows('update', new Post(1))).toBe(true);
    expect(await g.forUser({ id: 2 }).allows(PostPolicy, 'update', new Post(1))).toBe(true);
  });

  it('abstaining (undefined) falls through to the policy', async () => {
    const g = await gate({ decide: () => undefined });
    expect(await g.forUser({ id: 1 }).allows('update', new Post(1))).toBe(true);
    expect(await g.forUser({ id: 2 }).allows('update', new Post(1))).toBe(false);
  });

  it('receives the user, ability and resource', async () => {
    const decide = vi.fn().mockReturnValue(undefined);
    const post = new Post(9);
    await (await gate({ decide })).forUser({ id: 1 }).allows('update', post);
    expect(decide).toHaveBeenCalledWith({ id: 1 }, 'update', post);
  });

  it('runs AFTER superAdmin: a super-admin grant never reaches the provider', async () => {
    const decide = vi.fn().mockReturnValue(false);
    const g = await gate({ decide }, { superAdmin: (u) => (u as U).admin === true });
    expect(await g.forUser({ id: 5, admin: true }).allows('update', new Post(1))).toBe(true);
    expect(await g.forUser({ id: 5, admin: true }).allows(PostPolicy, 'update', new Post(1))).toBe(
      true,
    );
    expect(decide).not.toHaveBeenCalled();
  });

  it('superAdmin receives the resource (to scope a bypass)', async () => {
    const superAdmin = vi.fn().mockReturnValue(undefined);
    const post = new Post(1);
    const g = await gate(undefined, { superAdmin });
    await g.forUser({ id: 1 }).allows('update', post);
    expect(superAdmin).toHaveBeenCalledWith({ id: 1 }, 'update', post);
    superAdmin.mockClear();
    await g.forUser({ id: 1 }).allows(PostPolicy, 'update', post);
    expect(superAdmin).toHaveBeenCalledWith({ id: 1 }, 'update', post);
  });

  it('a deny beats a permission-provider grant', async () => {
    const permissions: PermissionProvider = { hasPermission: () => true };
    const g = await gate({ decide: () => false }, {}, permissions);
    expect(await g.forUser({ id: 1 }).allows('update', new Post(1))).toBe(false);
  });

  it('is consulted for guests (user null) and may allow them', async () => {
    const decide = vi.fn().mockReturnValue(true);
    expect(await (await gate({ decide })).forUser(null).allows('update', new Post(1))).toBe(true);
    expect(decide).toHaveBeenCalledWith(null, 'update', expect.any(Post));
  });

  it('authorize() throws the official AuthorizationError and publishes reason "decision-provider"', async () => {
    const seen: Array<Record<string, unknown>> = [];
    const listener = (m: unknown) => seen.push((m as { payload: Record<string, unknown> }).payload);
    subscribe(authzDecisionChannel.name, listener);
    try {
      const g = await gate({ decide: () => ({ allowed: false, message: 'blocked by PDP' }) });
      const err = await g
        .forUser({ id: 1 })
        .authorize('update', new Post(1))
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuthorizationError);
      expect((err as AuthorizationError).status).toBe(403);
      await new Promise((r) => setTimeout(r, 10));
      expect(seen).toEqual([
        expect.objectContaining({ allowed: false, reason: 'decision-provider' }),
      ]);
    } finally {
      unsubscribe(authzDecisionChannel.name, listener);
    }
  });

  it('allowsMany calls decideMany ONCE and uses its verdicts in order', async () => {
    const decide = vi.fn();
    const decideMany = vi.fn().mockResolvedValue([true, undefined, false]);
    const results = await (await gate({ decide, decideMany })).forUser({ id: 2 }).allowsMany([
      { ability: 'update', resource: new Post(1) },
      { ability: 'update', resource: new Post(2, 2) }, // abstain → policy (owner) → true
      { ability: 'update', resource: new Post(3, 2) },
    ]);
    expect(results.map((r) => r.allowed)).toEqual([true, true, false]);
    expect(decideMany).toHaveBeenCalledOnce();
    // The abstained item reaches the policy, whose AuthzPolicy before() asks `decide` itself.
    expect(decide).toHaveBeenCalledTimes(1);
  });

  it('allowsMany falls back to per-item decide when decideMany throws', async () => {
    const decide = vi.fn().mockReturnValue(true);
    const decideMany = vi.fn().mockRejectedValue(new Error('down'));
    const results = await (await gate({ decide, decideMany }))
      .forUser({ id: 2 })
      .allowsMany([{ ability: 'update', resource: new Post(1) }]);
    expect(results[0]?.allowed).toBe(true);
    expect(decide).toHaveBeenCalledOnce();
  });

  it('gate.scope uses planScope, and falls back to the policy scope when it abstains', async () => {
    const planned = await gate({ decide: () => undefined, planScope: () => scopeNone });
    expect(await planned.forUser({ id: 1 }).scope(Post)).toEqual(scopeNone);

    const abstain = await gate({ decide: () => undefined, planScope: () => undefined });
    expect(await abstain.forUser({ id: 1 }).scope(Post)).toEqual(eq('ownerId', 1));
  });

  it('gate.scope: superAdmin wins over planScope and receives the entity', async () => {
    const planScope = vi.fn().mockReturnValue(scopeNone);
    const superAdmin = vi.fn().mockReturnValue(true);
    const g = await gate({ decide: () => undefined, planScope }, { superAdmin });
    expect(await g.forUser({ id: 1 }).scope(Post)).toEqual({ kind: 'all' });
    expect(planScope).not.toHaveBeenCalled();
    expect(superAdmin).toHaveBeenCalledWith({ id: 1 }, 'viewAny', Post);
  });
});

describe('DecisionProvider on routes (official @Can)', () => {
  let close: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await close?.();
    close = undefined;
  });

  @Controller('posts')
  class PostController {
    @Patch(':id')
    @Can(PostPolicy, 'update', byId(Post))
    update() {
      return { ok: true };
    }

    @Patch(':id/publish')
    @Can(PermissionPolicy, 'has', permission('posts.publish'))
    publish() {
      return { ok: true };
    }
  }

  it('AuthzPolicy.before() asks the provider with the loaded resource; its verdict is final', async () => {
    const decide = vi.fn((user: unknown, _ability: string, post?: object) =>
      (user as U).id === 7 ? true : (post as Post).id === '2' ? false : undefined,
    );
    const { app } = await bootApp({
      controllers: [PostController],
      providers: [PostPolicy, { provide: DECISION_PROVIDER, useValue: { decide } }],
    });
    close = () => app.close();
    const http = app.getHttpServer();
    // Abstain → the policy (default resolver: ownerId undefined) denies.
    await request(http)
      .patch('/posts/1')
      .set(asUser({ id: 1 }))
      .expect(403);
    // Deny.
    await request(http)
      .patch('/posts/2')
      .set(asUser({ id: 1 }))
      .expect(403);
    // Allow beats the policy.
    await request(http)
      .patch('/posts/1')
      .set(asUser({ id: 7 }))
      .expect(200);
    expect(decide).toHaveBeenCalledWith({ id: 7 }, 'update', expect.any(Post));
  });

  it('a deny `message` does not reach the 403: the official guard answers with its own body', async () => {
    // @nestjs/authorization 0.1.3 has no deny-with-reason: a policy returns `true` or denies, and
    // the guard throws `ForbiddenException(undefined)`. The provider's message is dropped (README:
    // "Migrating from 0.8"). If a future official version carries a reason, this test fails.
    const decide = vi.fn(() => ({ allowed: false, message: 'Your role does not allow this.' }));
    const { app } = await bootApp({
      controllers: [PostController],
      providers: [PostPolicy, { provide: DECISION_PROVIDER, useValue: { decide } }],
    });
    close = () => app.close();
    const res = await request(app.getHttpServer())
      .patch('/posts/1')
      .set(asUser({ id: 1 }))
      .expect(403);
    expect(decide).toHaveBeenCalled();
    expect(res.body).toEqual({ statusCode: 403, message: 'Forbidden' });
    expect(JSON.stringify(res.body)).not.toContain('Your role does not allow this.');
  });

  it('is not asked for RolePolicy / PermissionPolicy abilities', async () => {
    const decide = vi.fn(() => true);
    const { app } = await bootApp({
      controllers: [PostController],
      providers: [PostPolicy, { provide: DECISION_PROVIDER, useValue: { decide } }],
      permissions: { hasPermission: () => false },
    });
    close = () => app.close();
    await request(app.getHttpServer())
      .patch('/posts/1/publish')
      .set(asUser({ id: 1 }))
      .expect(403);
    expect(decide).not.toHaveBeenCalled();
  });
});
