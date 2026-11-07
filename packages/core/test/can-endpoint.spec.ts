import 'reflect-metadata';
import { AuthorizationModule } from '@nestjs/authorization';
import {
  type CanActivate,
  type DynamicModule,
  type ExecutionContext,
  HttpException,
  type INestApplication,
  Injectable,
  SetMetadata,
  type Type,
  UseGuards,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { PolicyFor } from '../src/links.js';
import { AuthzModule } from '../src/module.js';
import type { AuthzModuleOptions, ResourceLoaderMap } from '../src/types.js';

class Post {
  constructor(
    readonly id: number,
    readonly ownerId: number,
  ) {}
}

@PolicyFor(Post)
class PostPolicy {
  // class-level abilities (no resource): user #1 may create, may not publish.
  create(user: { id: number } | null) {
    return user?.id === 1;
  }
  publish() {
    return false;
  }
  // instance ability: only the owner may update.
  update(user: { id: number } | null, post: Post) {
    return user?.id === post.ownerId;
  }
}

// The official guard's user: always "user #1".
const official = AuthorizationModule.forRoot({ getUser: () => ({ id: 1 }) });

async function bootstrap(canEndpoint: boolean | string | undefined): Promise<INestApplication> {
  const mod = await Test.createTestingModule({
    imports: [official, AuthzModule.forRoot(canEndpoint === undefined ? {} : { canEndpoint })],
    providers: [PostPolicy],
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
      imports: [official, AuthzModule.forRoot({ canEndpoint: true, resourceLoaders })],
      providers: [PostPolicy],
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
        official,
        AuthzModule.forRootAsync({
          // canEndpoint is declared statically (controllers register before the
          // factory resolves); resourceLoaders are read from the resolved options.
          canEndpoint: true,
          useFactory: (): AuthzModuleOptions => ({
            resourceLoaders: { Post: (id) => new Post(Number(id), 1) },
          }),
        }),
      ],
      providers: [PostPolicy],
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'update', resource: { type: 'Post', id: 1 } })
      .expect(201, { allowed: true });
  });
});

describe('POST /authz/can — batch (array body)', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('returns one verdict per item, in order, for an array body', async () => {
    app = await bootstrap(true);
    const res = await request(app.getHttpServer())
      .post('/authz/can')
      .send([{ ability: 'create' }, { ability: 'publish' }])
      .expect(201);
    expect(res.body).toEqual([
      { ability: 'create', allowed: true },
      { ability: 'publish', allowed: false },
    ]);
  });

  it('echoes the resource shim and rehydrates per-item via resourceLoaders', async () => {
    const mod = await Test.createTestingModule({
      imports: [
        official,
        AuthzModule.forRoot({
          canEndpoint: true,
          resourceLoaders: { Post: (id) => new Post(Number(id), Number(id) === 1 ? 1 : 2) },
        }),
      ],
      providers: [PostPolicy],
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    const res = await request(app.getHttpServer())
      .post('/authz/can')
      .send([
        { ability: 'update', resource: { type: 'Post', id: 1 } }, // owner #1 → allow
        { ability: 'update', resource: { type: 'Post', id: 2 } }, // owner #2 → deny
      ])
      .expect(201);
    expect(res.body).toEqual([
      { ability: 'update', resource: { type: 'Post', id: 1 }, allowed: true },
      { ability: 'update', resource: { type: 'Post', id: 2 }, allowed: false },
    ]);
  });

  it('an empty array returns an empty array', async () => {
    app = await bootstrap(true);
    const res = await request(app.getHttpServer()).post('/authz/can').send([]).expect(201);
    expect(res.body).toEqual([]);
  });
});

describe('the controllers AuthzModule mounts: open by default, `decorators` applied', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  /** A guard that answers 418 unless the request carries `x-key: secret`. */
  @Injectable()
  class KeyGuard implements CanActivate {
    canActivate(ctx: ExecutionContext): boolean {
      const key = ctx.switchToHttp().getRequest<{ headers: Record<string, string> }>().headers[
        'x-key'
      ];
      if (key !== 'secret') throw new HttpException('no key', 418);
      return true;
    }
  }

  const Tagged = (tag: string): ClassDecorator => SetMetadata('test:tag', tag);

  function mountedController(module: DynamicModule): Type<unknown> {
    const [controller] = (module.controllers ?? []) as Type<unknown>[];
    if (!controller) throw new Error('no controller mounted');
    return controller;
  }

  it('marks every mounted controller open to the official guard (authorization:can-anyone)', () => {
    const controller = mountedController(AuthzModule.forRoot({ canEndpoint: true }));
    expect(Reflect.getMetadata('authorization:can-anyone', controller)).toBe(true);
    const asyncController = mountedController(
      AuthzModule.forRootAsync({ canEndpoint: true, useFactory: () => ({}) }),
    );
    expect(Reflect.getMetadata('authorization:can-anyone', asyncController)).toBe(true);
  });

  it('applies `decorators` to the controller, without leaking between registrations', () => {
    const tagged = mountedController(
      AuthzModule.forRoot({ canEndpoint: true, decorators: [Tagged('first')] }),
    );
    const other = mountedController(
      AuthzModule.forRootAsync({
        canEndpoint: 'other/can',
        decorators: [Tagged('second')],
        useFactory: () => ({}),
      }),
    );
    const plain = mountedController(AuthzModule.forRoot({ canEndpoint: true }));
    expect(Reflect.getMetadata('test:tag', tagged)).toBe('first');
    expect(Reflect.getMetadata('test:tag', other)).toBe('second');
    expect(Reflect.getMetadata('test:tag', plain)).toBeUndefined();
    expect(tagged).not.toBe(plain);
  });

  it('a guard given in `decorators` runs on the endpoint', async () => {
    const mod = await Test.createTestingModule({
      imports: [
        official,
        AuthzModule.forRoot({ canEndpoint: true, decorators: [UseGuards(KeyGuard)] }),
      ],
      providers: [PostPolicy],
    }).compile();
    app = mod.createNestApplication({ logger: false });
    await app.init();
    await request(app.getHttpServer()).post('/authz/can').send({ ability: 'create' }).expect(418);
    await request(app.getHttpServer())
      .post('/authz/can')
      .set('x-key', 'secret')
      .send({ ability: 'create' })
      .expect(201, { allowed: true });
  });

  it('the endpoint answers guests under the official global guard (no @Can needed)', async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot(), AuthzModule.forRoot({ canEndpoint: true })],
      providers: [PostPolicy],
    }).compile();
    app = mod.createNestApplication({ logger: false });
    await app.init();
    await request(app.getHttpServer())
      .post('/authz/can')
      .send({ ability: 'create' })
      .expect(201, { allowed: false });
  });

  it('fails the startup when the forRootAsync() factory returns `decorators`', async () => {
    await expect(
      Test.createTestingModule({
        imports: [
          official,
          AuthzModule.forRootAsync({
            canEndpoint: true,
            useFactory: (): AuthzModuleOptions => ({ decorators: [Tagged('late')] }),
          }),
        ],
      }).compile(),
    ).rejects.toThrow(/`decorators` is in the options the forRootAsync\(\) factory returned/);
  });
});
