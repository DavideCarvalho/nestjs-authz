import 'reflect-metadata';
import {
  Controller,
  type ExecutionContext,
  Get,
  type INestApplication,
  Param,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Can } from '../src/decorator/can.decorator.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { AuthzModule } from '../src/module.js';
import type { ResourceResolver } from '../src/resource-resolver.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';

class Post {
  constructor(
    public id: number,
    public authorId: number,
  ) {}
}

@Policy(Post)
class PostPolicy {
  view(_user: { id: number }, post: Post) {
    return post.authorId === 1; // only author #1's posts are viewable
  }
  // class-level ability: granted for any authenticated user in this test
  create(user: { id: number }) {
    return user !== undefined;
  }
}

// Resolver returns a Post owned by author #1 for id<100, else #2.
class TestResourceResolver implements ResourceResolver {
  resolve(_resource: unknown, ctx: ExecutionContext): Post | undefined {
    const req = ctx.switchToHttp().getRequest<{ params: { id: string } }>();
    const id = Number(req.params.id);
    if (id === 0) return undefined; // simulate not-found
    return new Post(id, id < 100 ? 1 : 2);
  }
}

@Controller('posts')
class PostController {
  @Get(':id')
  @Can('view', Post)
  view(@Param('id') id: string) {
    return { id };
  }

  @Get()
  @Can('create', Post, { classLevel: true })
  create() {
    return { ok: true };
  }
}

// Stub context accessor: always "user #1, verified".
const stubContext = {
  userRef: () => ({ type: 'User', id: 1 }),
};

describe('CanGuard (Nest testing module)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const mod = await Test.createTestingModule({
      imports: [
        AuthzModule.forRoot({
          policies: [PostPolicy],
          resourceResolver: new TestResourceResolver(),
        }),
      ],
      controllers: [PostController],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('allows when policy grants (author #1 post)', async () => {
    await request(app.getHttpServer()).get('/posts/5').expect(200, { id: '5' });
  });

  it('denies with 403 when policy refuses (author #2 post)', async () => {
    await request(app.getHttpServer()).get('/posts/150').expect(403);
  });

  it('denies with 403 when resource is not found', async () => {
    await request(app.getHttpServer()).get('/posts/0').expect(403);
  });

  it('class-level ability skips resource loading and allows', async () => {
    await request(app.getHttpServer()).get('/posts').expect(200, { ok: true });
  });
});
