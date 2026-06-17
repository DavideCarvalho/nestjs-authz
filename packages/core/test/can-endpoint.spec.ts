import 'reflect-metadata';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { AuthzModule } from '../src/module.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';

class Post {}

@Policy(Post)
class PostPolicy {
  // class-level abilities (no resource): user #1 may create, may not publish.
  create(user: { id: number } | undefined) {
    return user?.id === 1;
  }
  publish() {
    return false;
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
