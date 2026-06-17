import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import type { ContextAccessor, UserRef } from '../src/context-accessor.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';

class Note {
  constructor(
    public id: number,
    public ownerId: number,
  ) {}
}

@Policy(Note)
class NotePolicy {
  update(user: UserRef, note: Note) {
    return Number(user.id) === note.ownerId;
  }
}

function makeContext(ref: UserRef | undefined): ContextAccessor {
  return {
    userRef: () => ref,
    traceId: () => undefined,
    tenantId: () => undefined,
    get: () => undefined,
  };
}

describe('current user via ContextAccessor', () => {
  it('reads the current user from a structural context accessor', async () => {
    const registry = new PolicyRegistry();
    registry.register(new NotePolicy());
    const gate = new Gate(registry, {}, makeContext({ type: 'User', id: 7 }));

    expect(await gate.allows('update', new Note(1, 7))).toBe(true);
    expect(await gate.allows('update', new Note(1, 8))).toBe(false);
  });

  it('denies when the accessor returns no userRef (unauthenticated)', async () => {
    const registry = new PolicyRegistry();
    registry.register(new NotePolicy());
    const gate = new Gate(registry, {}, makeContext(undefined));

    expect(await gate.allows('update', new Note(1, 7))).toBe(false);
  });

  it('explicit forUser overrides the context accessor', async () => {
    const registry = new PolicyRegistry();
    registry.register(new NotePolicy());
    const gate = new Gate(registry, {}, makeContext({ type: 'User', id: 7 }));

    // context says user 7, but we authorize as user 8 explicitly
    expect(await gate.forUser({ id: 8 }).allows('update', new Note(1, 8))).toBe(true);
  });

  // --- P3: resolveUser hydration on the context path ---

  it('without resolveUser, policies receive only the {type,id} ref (no entity fields)', async () => {
    @Policy(class Adminable {})
    class AdminablePolicy {
      // expects a hydrated entity with `isAdmin` — which the bare ref never has
      manage(user: { isAdmin?: boolean }) {
        return user.isAdmin === true;
      }
    }
    const registry = new PolicyRegistry();
    registry.register(new AdminablePolicy());
    // superAdmin reads `isAdmin`, but the context path only sees {type,id}.
    const gate = new Gate(
      registry,
      { superAdmin: (u) => (u as { isAdmin?: boolean }).isAdmin === true },
      makeContext({ type: 'User', id: 7 }),
    );
    // Neither superAdmin nor the policy can see `isAdmin` → denied.
    expect(await gate.allows('manage')).toBe(false);
  });

  it('with resolveUser, superAdmin fires on the context path (entity hydrated from ref)', async () => {
    @Policy(class Adminable {})
    class AdminablePolicy {
      manage() {
        return false; // policy would always deny — only superAdmin can grant
      }
    }
    const registry = new PolicyRegistry();
    registry.register(new AdminablePolicy());

    // The "DB": ref id 7 → an admin entity.
    const gate = new Gate(
      registry,
      {
        superAdmin: (u) => (u as { isAdmin?: boolean }).isAdmin === true,
        resolveUser: (ref: UserRef) =>
          Number(ref.id) === 7 ? { id: ref.id, isAdmin: true } : { id: ref.id, isAdmin: false },
      },
      makeContext({ type: 'User', id: 7 }),
    );

    // superAdmin sees the hydrated `isAdmin: true` → granted on the context path.
    expect(await gate.allows('manage')).toBe(true);
  });

  it('resolveUser returning nullish maps to the deny (NO_USER) path', async () => {
    const registry = new PolicyRegistry();
    registry.register(new NotePolicy());
    const gate = new Gate(
      registry,
      { resolveUser: () => undefined },
      makeContext({ type: 'User', id: 7 }),
    );
    expect(await gate.allows('update', new Note(1, 7))).toBe(false);
  });

  // --- P5: forUser(nullish) is an explicit anonymous request → deny, never throws ---

  it('forUser(undefined).authorize DENIES rather than throwing a TypeError/500', async () => {
    const registry = new PolicyRegistry();
    registry.register(new NotePolicy());
    const gate = new Gate(registry, {}, makeContext(undefined));

    expect(await gate.forUser(undefined).allows('update', new Note(1, 7))).toBe(false);
    await expect(gate.forUser(undefined).authorize('update', new Note(1, 7))).rejects.toThrow(
      ForbiddenException,
    );
    // null behaves identically.
    expect(await gate.forUser(null).allows('update', new Note(1, 7))).toBe(false);
  });
});
