import 'reflect-metadata';
import { AuthenticationContext, AuthenticationModule } from '@nestjs/authentication';
import { AuthorizationModule, Policy } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { describe, expect, it, vi } from 'vitest';
import type { ContextAccessor, UserRef } from '../src/context-accessor.js';
import { Gate } from '../src/gate.js';
import { PolicyFor } from '../src/links.js';
import { AuthzModule } from '../src/module.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';
import type { AuthzModuleOptions } from '../src/types.js';

class Post {
  constructor(readonly authorId: number) {}
}

@Policy()
@PolicyFor(Post)
class PostPolicy {
  update(user: { id: number } | null, post: Post) {
    return user?.id === post.authorId;
  }
}

function nestjsContext(ref: UserRef | undefined): ContextAccessor {
  const store = {};
  return {
    traceId: () => undefined,
    tenantId: () => undefined,
    userRef: () => ref,
    get: () => store,
  };
}

async function boot(options: {
  authentication: boolean;
  ref?: UserRef;
  authz?: AuthzModuleOptions;
}) {
  const mod = await Test.createTestingModule({
    imports: [
      ...(options.authentication ? [AuthenticationModule.forRoot()] : []),
      AuthorizationModule.forRoot(),
      AuthzModule.forRoot(options.authz ?? {}),
    ],
    providers: [
      PostPolicy,
      ...(options.ref ? [{ provide: CONTEXT_ACCESSOR, useValue: nestjsContext(options.ref) }] : []),
    ],
  }).compile();
  mod.useLogger(false);
  await mod.init();
  return {
    gate: mod.get(Gate),
    auth: options.authentication ? mod.get(AuthenticationContext) : undefined,
  };
}

describe('the ambient user of Gate calls made without forUser()', () => {
  it("reads @nestjs/authentication's AuthenticationContext.user first", async () => {
    const resolveUser = vi.fn((ref: UserRef) => ({ id: Number(ref.id) }));
    const { gate, auth } = await boot({
      authentication: true,
      ref: { type: 'user', id: 2 },
      authz: { resolveUser },
    });
    const allowed = await auth?.run({ user: { id: 1 } }, () => gate.allows('update', new Post(1)));
    expect(allowed).toBe(true);
    // nestjs-context was not asked.
    expect(resolveUser).not.toHaveBeenCalled();
  });

  it('an anonymous call in the authentication scope is a guest: nestjs-context is not asked', async () => {
    const resolveUser = vi.fn((ref: UserRef) => ({ id: Number(ref.id) }));
    const { gate, auth } = await boot({
      authentication: true,
      ref: { type: 'user', id: 2 },
      authz: { resolveUser },
    });
    expect(await auth?.run(null, () => gate.allows('update', new Post(2)))).toBe(false);
    await expect(
      auth?.run(null, () => gate.authorize('update', new Post(2))),
    ).rejects.toMatchObject({ status: 401 });
    expect(resolveUser).not.toHaveBeenCalled();
  });

  it('falls back to nestjs-context outside any authentication scope', async () => {
    const resolveUser = vi.fn((ref: UserRef) => ({ id: Number(ref.id) }));
    const { gate } = await boot({
      authentication: true,
      ref: { type: 'user', id: 2 },
      authz: { resolveUser },
    });
    // A queue worker or cron job: @nestjs/authentication is set up, but no call is handled.
    expect(await gate.allows('update', new Post(2))).toBe(true);
    expect(resolveUser).toHaveBeenCalledTimes(1);
  });

  it('uses nestjs-context when @nestjs/authentication is not set up', async () => {
    const { gate } = await boot({ authentication: false, ref: { type: 'user', id: 3 } });
    expect(await gate.allows('update', new Post(3))).toBe(true);
    expect(await gate.allows('update', new Post(4))).toBe(false);
  });

  it('is a guest without either', async () => {
    const { gate } = await boot({ authentication: false });
    expect(await gate.allows('update', new Post(1))).toBe(false);
    await expect(gate.authorize('update', new Post(1))).rejects.toMatchObject({ status: 401 });
  });
});
