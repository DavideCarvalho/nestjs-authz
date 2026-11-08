import 'reflect-metadata';
import { Can, Policy } from '@nestjs/authorization';
import { Controller, Get, type INestApplication, Req } from '@nestjs/common';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { Permission, Roles } from '../src/decorator/roles.decorator.js';
import { ability, authorizedResource, byId, permission, roles } from '../src/helpers.js';
import { PolicyFor } from '../src/links.js';
import { AuthzPolicy } from '../src/policies/authz-policy.js';
import { GatePolicy } from '../src/policies/gate.policy.js';
import { PermissionPolicy } from '../src/policies/permission.policy.js';
import { RolePolicy } from '../src/policies/role.policy.js';
import { IdParamResourceResolver, type ResourceResolver } from '../src/resource-resolver.js';
import { asUser, bootApp, permissionTable, roleTable } from './support/app.js';

interface User {
  id: number;
  roles?: string[];
  root?: boolean;
}

class Post {
  constructor(
    public id: number,
    public authorId: number,
  ) {}
}

@Policy()
@PolicyFor(Post)
class PostPolicy extends AuthzPolicy {
  view(user: User | null, post: Post) {
    return post.authorId === user?.id;
  }
  create(user: User | null) {
    return user !== null;
  }
}

class Comment {
  id?: string;
}

/** Linked with `@PolicyFor` alone (which applies the official `@Policy()`). */
@PolicyFor(Comment)
class CommentPolicy {
  edit(user: User | null, comment: Comment) {
    return user?.id === Number(comment.id);
  }
  create(user: User | null) {
    return user?.id === 1;
  }
}

/** Posts below 100 belong to author #1, the rest to #2; id 0 does not exist. */
const fallback = new IdParamResourceResolver();
const resolver: ResourceResolver = {
  resolve(resource, ctx) {
    if (resource !== Post) return fallback.resolve(resource, ctx);
    const id = Number(ctx.switchToHttp().getRequest<{ params: { id: string } }>().params.id);
    return id === 0 ? undefined : new Post(id, id < 100 ? 1 : 2);
  },
};

@Controller('posts')
class PostController {
  @Get('mine')
  @Can.Anyone()
  mine() {
    return { ok: true };
  }

  @Get('undeclared')
  undeclared() {
    return { ok: true };
  }

  @Get('new')
  @Can(PostPolicy, 'create')
  create() {
    return { ok: true };
  }

  @Get('admin')
  @Roles('admin')
  admin() {
    return { ok: true };
  }

  @Get('editors')
  @Can(RolePolicy, 'hasAll', roles('admin', 'editor'))
  editors() {
    return { ok: true };
  }

  @Get('publish')
  @Permission('posts.publish')
  publish() {
    return { ok: true };
  }

  @Get('moderate')
  @Can(PermissionPolicy, 'hasAll', permission('posts.publish', 'posts.delete'))
  moderate() {
    return { ok: true };
  }

  @Get(':id')
  @Can(PostPolicy, 'view', byId(Post))
  view(@Req() req: object) {
    return { title: `post ${authorizedResource(req, Post)?.id}` };
  }
}

@Controller('comments')
class CommentController {
  @Get('admin')
  @Can(GatePolicy, 'allows', ability('access-admin'))
  admin() {
    return { ok: true };
  }

  @Get(':id')
  @Can(CommentPolicy, 'edit', byId(Comment))
  edit() {
    return { ok: true };
  }
}

describe('routes on the official guard', () => {
  let app: INestApplication;

  afterEach(async () => {
    await app?.close();
  });

  async function boot() {
    const permissions = permissionTable({ '1': ['posts.*'], '2': ['posts.publish'] });
    ({ app } = await bootApp({
      controllers: [PostController, CommentController],
      providers: [PostPolicy, CommentPolicy],
      authz: { resourceResolver: resolver, superAdmin: (u) => (u as User | null)?.root === true },
      permissions: permissions.provider,
      roles: roleTable({ '3': ['editor'] }),
    }));
    return app.getHttpServer();
  }

  it('byId(Post) loads the record for the policy, and keeps it for the handler', async () => {
    const http = await boot();
    await request(http)
      .get('/posts/5')
      .set(asUser({ id: 1 }))
      .expect(200, { title: 'post 5' });
    await request(http)
      .get('/posts/150')
      .set(asUser({ id: 1 }))
      .expect(403);
  });

  it('a record that is not found is a 403 before the policy runs', async () => {
    const http = await boot();
    await request(http)
      .get('/posts/0')
      .set(asUser({ id: 1 }))
      .expect(403);
  });

  it('a guest is answered 401 by the official guard', async () => {
    const http = await boot();
    await request(http).get('/posts/new').expect(401);
    await request(http)
      .get('/posts/new')
      .set(asUser({ id: 9 }))
      .expect(200);
  });

  it('denies handlers that declare no check (the official default), opens Can.Anyone()', async () => {
    const http = await boot();
    await request(http)
      .get('/posts/undeclared')
      .set(asUser({ id: 1 }))
      .expect(403);
    await request(http).get('/posts/mine').expect(200);
  });

  it('@Roles reads roles off the user and from the role store', async () => {
    const http = await boot();
    await request(http)
      .get('/posts/admin')
      .set(asUser({ id: 1, roles: ['admin'] }))
      .expect(200);
    await request(http)
      .get('/posts/admin')
      .set(asUser({ id: 2 }))
      .expect(403);
    await request(http)
      .get('/posts/editors')
      .set(asUser({ id: 3, roles: ['admin'] }))
      .expect(200);
    await request(http)
      .get('/posts/editors')
      .set(asUser({ id: 4, roles: ['admin'] }))
      .expect(403);
  });

  it('@Permission / PermissionPolicy honor wildcard grants', async () => {
    const http = await boot();
    await request(http)
      .get('/posts/publish')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/posts/publish')
      .set(asUser({ id: 2 }))
      .expect(200);
    await request(http)
      .get('/posts/moderate')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/posts/moderate')
      .set(asUser({ id: 2 }))
      .expect(403);
    await request(http)
      .get('/posts/publish')
      .set(asUser({ id: 5 }))
      .expect(403);
  });

  it('superAdmin grants through AuthzPolicy and the built-in policies', async () => {
    const http = await boot();
    const root = asUser({ id: 7, root: true });
    await request(http).get('/posts/150').set(root).expect(200);
    await request(http).get('/posts/admin').set(root).expect(200);
    await request(http).get('/posts/moderate').set(root).expect(200);
    // CommentPolicy does not extend AuthzPolicy: superAdmin does not reach it.
    await request(http).get('/comments/3').set(root).expect(403);
  });

  it('byId(Comment) runs the policy linked with @PolicyFor alone', async () => {
    const http = await boot();
    await request(http)
      .get('/comments/3')
      .set(asUser({ id: 3 }))
      .expect(200);
    await request(http)
      .get('/comments/3')
      .set(asUser({ id: 4 }))
      .expect(403);
  });

  it('GatePolicy runs a gate.define() gate', async () => {
    const http = await boot();
    const { Gate } = await import('../src/gate.js');
    app.get(Gate).define('access-admin', (u) => (u as User).id === 1);
    await request(http)
      .get('/comments/admin')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/comments/admin')
      .set(asUser({ id: 2 }))
      .expect(403);
  });
});
