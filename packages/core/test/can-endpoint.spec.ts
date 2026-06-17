import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { AuthzModule } from '../src/module.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';
import type { AuthzModuleOptions, ResourceLoaderMap } from '../src/types.js';

class Post {
  constructor(
    readonly id: number,
    readonly ownerId: number,
  ) {}
}

@Policy(Post)
class PostPolicy {
  // class-level abilities (no resource): user #1 may create, may not publish.
  create(user: { id: number } | undefined) {
    return user?.id === 1;
  }
  publish() {
    return false;
  }
  // instance ability: only the owner may update.
  update(user: { id: number } | undefined, post: Post) {
    return user?.id === post.ownerId;
  }
}

// Always "user #1".
const stubContext = { userRef: () => ({ type: 'User', id: 1 }) };

async function bootstrap(canEndpoint: boolean | string | undefined): Promise<INestApplication> {
  const mod = await Test.createTestingModule({
    imports: [AuthzModule.forRoot({ policies: [PostPolicy], canEndpoint })],
    providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
  }).compile();
  const app = mod.createNestApplication();
  await app.init();
  return app;
}

describe('POST /authz/can (opt-in fallback endpoint)', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('returns { allowed: true } when the gate grants the ability', async () => {
    app = await bootstrap(true);
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'create' })
      .expect(201, { allowed: true });
  });

  it('returns { allowed: false } when the gate denies the ability', async () => {
    app = await bootstrap(true);
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'publish' })
      .expect(201, { allowed: false });
  });

  it('fails closed ({ allowed: false }) for an unknown ability', async () => {
    app = await bootstrap(true);
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'does-not-exist' })
      .expect(201, { allowed: false });
  });

  it('mounts at a custom path when canEndpoint is a string', async () => {
    app = await bootstrap('api/authz/can');
    await request(app.getHttpServer())
      .post('/api/authz/can')
      .send({ ability: 'create' })
      .expect(201, { allowed: true });
    await request(app.getHttpServer()).post('/authz/can').send({ ability: 'create' }).expect(404);
  });

  it('is absent (404) when canEndpoint is off by default', async () => {
    app = await bootstrap(undefined);
    await request(app.getHttpServer()).post('/authz/can').send({ ability: 'create' }).expect(404);
  });
});

describe('POST /authz/can resource rehydration (resourceLoaders)', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  async function bootstrapWithLoaders(
    resourceLoaders: ResourceLoaderMap,
  ): Promise<INestApplication> {
    const mod = await Test.createTestingModule({
      imports: [
        AuthzModule.forRoot({ policies: [PostPolicy], canEndpoint: true, resourceLoaders }),
      ],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    const a = mod.createNestApplication();
    await a.init();
    return a;
  }

  it('loads the real instance so an owner-bound ability ALLOWS for the owner', async () => {
    // Context user is #1; loader builds a Post owned by #1.
    app = await bootstrapWithLoaders({ Post: (id) => new Post(Number(id), 1) });
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'update', resource: { type: 'Post', id: 1 } })
      .expect(201, { allowed: true });
  });

  it('DENIES the same ability when the loaded instance is owned by someone else', async () => {
    // Context user is #1; loader builds a Post owned by #2.
    app = await bootstrapWithLoaders({ Post: (id) => new Post(Number(id), 2) });
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'update', resource: { type: 'Post', id: 1 } })
      .expect(201, { allowed: false });
  });

  it('treats a loader returning undefined as not found ({ allowed: false })', async () => {
    app = await bootstrapWithLoaders({ Post: () => undefined });
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'update', resource: { type: 'Post', id: 99 } })
      .expect(201, { allowed: false });
  });

  it('falls back to prior behavior (instance ability denies) when no loader for the type', async () => {
    // canEndpoint on, but NO loaders → { type, id } shim forwarded as-is, never
    // matches the @Policy by constructor, so the instance ability denies (no crash).
    app = await bootstrapWithLoaders({ Comment: (id) => ({ id }) });
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'update', resource: { type: 'Post', id: 1 } })
      .expect(201, { allowed: false });
    // Class-level abilities still resolve unaffected.
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'create' })
      .expect(201, { allowed: true });
  });

  it('wires resourceLoaders through forRootAsync too', async () => {
    const mod = await Test.createTestingModule({
      imports: [
        AuthzModule.forRootAsync({
          // canEndpoint is declared statically (controllers register before the
          // factory resolves); resourceLoaders are read from the resolved options.
          canEndpoint: true,
          useFactory: (): AuthzModuleOptions => ({
            policies: [PostPolicy],
            resourceLoaders: { Post: (id) => new Post(Number(id), 1) },
          }),
        }),
      ],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'update', resource: { type: 'Post', id: 1 } })
      .expect(201, { allowed: true });
  });
});
