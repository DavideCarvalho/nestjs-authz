import 'reflect-metadata';
import { AuthzModule, CONTEXT_ACCESSOR, Gate, Policy } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { authorizeResource, authorizeResourceForUser } from '../src/authorize-resource.js';

class Post {
  constructor(
    public id: number,
    public authorId: number,
  ) {}
}

@Policy(Post)
class PostPolicy {
  update(user: { id: number }, post: Post) {
    return post.authorId === user.id;
  }
  delete(user: { id: number }, post: Post) {
    return user.id === 1 && post.authorId === user.id;
  }
}

// Current context user: #1.
const stubContext = { userRef: () => ({ type: 'User', id: 1 }) };

describe('authorizeResource — per-instance can map (no request)', () => {
  let gate: Gate;

  beforeEach(async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot({ policies: [PostPolicy] })],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    await mod.init();
    gate = mod.get(Gate);
  });

  it('returns the right verdicts for an owned post (context user #1)', async () => {
    const post = new Post(10, 1);
    const can = await authorizeResource(gate, post, ['update', 'delete']);
    expect(can).toEqual({ update: true, delete: true });
  });

  it('denies for a post owned by someone else', async () => {
    const post = new Post(11, 2);
    const can = await authorizeResource(gate, post, ['update', 'delete']);
    expect(can).toEqual({ update: false, delete: false });
  });

  it('authorizeResourceForUser checks an explicit user', async () => {
    const post = new Post(12, 2);
    const can = await authorizeResourceForUser(gate, { id: 2 }, post, ['update', 'delete']);
    // user #2 owns it → update allowed; delete requires id===1 → denied.
    expect(can).toEqual({ update: true, delete: false });
  });
});
