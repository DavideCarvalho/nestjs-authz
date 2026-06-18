import 'reflect-metadata';
import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { PolicyRegistry } from '../src/policy-registry.js';

class Doc {
  constructor(
    public id: number,
    public ownerId: number,
  ) {}
}

@Policy(Doc)
class DocPolicy {
  // Returns the richer `{ allowed, message }` shape on denial; a bare boolean on allow.
  update(user: { id: number }, doc: Doc) {
    if (doc.ownerId === user.id) return true;
    return { allowed: false, message: 'You can only update your own documents.' };
  }
  // Bare-boolean denial keeps the generic message (backward compatible).
  delete(user: { id: number }, doc: Doc) {
    return doc.ownerId === user.id;
  }
}

function makeGate(): Gate {
  const registry = new PolicyRegistry();
  registry.register(new DocPolicy());
  return new Gate(registry, {}, undefined);
}

describe('deny reason / message surfaced on ForbiddenException', () => {
  it('authorize() throws ForbiddenException carrying the policy message', async () => {
    const gate = makeGate();
    const doc = new Doc(1, 999);
    try {
      await gate.forUser({ id: 1 }).authorize('update', doc);
      throw new Error('expected authorize to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(ForbiddenException);
      const body = (err as ForbiddenException).getResponse() as Record<string, unknown>;
      expect(body.message).toBe('You can only update your own documents.');
      expect(body.ability).toBe('update');
      expect(body.reason).toBe('policy');
    }
  });

  it('a richer-shape allow still permits (backward compatible verdict)', async () => {
    const gate = makeGate();
    const doc = new Doc(1, 1);
    await expect(gate.forUser({ id: 1 }).authorize('update', doc)).resolves.toBeUndefined();
  });

  it('a bare-boolean denial keeps the generic Unauthorized message', async () => {
    const gate = makeGate();
    const doc = new Doc(1, 999);
    try {
      await gate.forUser({ id: 1 }).authorize('delete', doc);
      throw new Error('expected authorize to throw');
    } catch (err) {
      const body = (err as ForbiddenException).getResponse() as Record<string, unknown>;
      expect(body.message).toBe('Unauthorized: delete');
      expect(body.reason).toBe('policy');
    }
  });

  it('a message-bearing allow does not throw and carries no error', async () => {
    const registry = new PolicyRegistry();
    @Policy(Doc)
    class P {
      view() {
        return { allowed: true, message: 'ignored on allow' };
      }
    }
    registry.register(new P());
    const gate = new Gate(registry, {}, undefined);
    expect(await gate.forUser({ id: 1 }).allows('view', new Doc(1, 1))).toBe(true);
  });
});
