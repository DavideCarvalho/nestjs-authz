import 'reflect-metadata';
import { subscribe, unsubscribe } from 'node:diagnostics_channel';
import { Can, Policy } from '@nestjs/authorization';
import { Controller, Get, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { authzDecisionChannel } from '../src/diagnostics.js';
import { byId } from '../src/helpers.js';
import { PolicyFor } from '../src/links.js';
import { asUser, bootApp } from './support/app.js';

class Post {
  id?: string;
}

@Policy()
@PolicyFor(Post)
class PostPolicy {
  view(user: { id: number } | null, post: Post) {
    return String(user?.id) === post.id;
  }
}

@Controller('posts')
class PostController {
  @Get(':id')
  @Can(PostPolicy, 'view', byId(Post))
  view() {
    return { ok: true };
  }
}

describe('the authz:decision channel (allow + deny)', () => {
  let app: INestApplication | undefined;
  const seen: Array<Record<string, unknown>> = [];
  const listener = (message: unknown) => {
    seen.push(
      (message as { payload?: Record<string, unknown> }).payload ??
        (message as Record<string, unknown>),
    );
  };

  beforeEach(() => {
    seen.length = 0;
    subscribe(authzDecisionChannel.name, listener);
  });

  afterEach(async () => {
    unsubscribe(authzDecisionChannel.name, listener);
    await app?.close();
    app = undefined;
  });

  const settle = () => new Promise((r) => setTimeout(r, 10));

  it('publishes the official guard decisions, allowed and denied', async () => {
    ({ app } = await bootApp({ controllers: [PostController], providers: [PostPolicy] }));
    await request(app.getHttpServer())
      .get('/posts/1')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(app.getHttpServer())
      .get('/posts/2')
      .set(asUser({ id: 1 }))
      .expect(403);
    await settle();
    expect(seen).toEqual([
      expect.objectContaining({
        ability: 'view',
        allowed: true,
        reason: 'route',
        policy: 'PostPolicy',
        handler: 'PostController.view',
        resourceType: 'Post',
        resourceId: '1',
      }),
      expect.objectContaining({
        ability: 'view',
        allowed: false,
        reason: 'route',
        policy: 'PostPolicy',
        handler: 'PostController.view',
        resourceId: '2',
      }),
    ]);
  });

  it('publishes Gate decisions once each, authorize() included', async () => {
    const { gate } = await bootApp({ providers: [PostPolicy] }).then((r) => {
      app = r.app;
      return r;
    });
    const post = Object.assign(new Post(), { id: '3' });
    await gate.forUser({ id: 3 }).allows('view', post);
    await gate
      .forUser({ id: 4 })
      .authorize('view', post)
      .catch(() => undefined);
    await settle();
    expect(seen.map((d) => [d.allowed, d.reason, d.handler])).toEqual([
      [true, 'policy', null],
      [false, 'policy', null],
    ]);
  });
});
