import diagnostics_channel from 'node:diagnostics_channel';
import { AUTHZ_DECISION_CHANNEL, type AuthzDecisionDiagnostic } from '@dudousxd/nestjs-authz';
import { collectWatcherEntries } from '@dudousxd/nestjs-telescope-testing';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type AuthorizationEntryContent,
  AuthorizationWatcher,
} from '../src/authorization.watcher.js';

const channel = diagnostics_channel.channel(AUTHZ_DECISION_CHANNEL);

function publish(over: Partial<AuthzDecisionDiagnostic>): void {
  const payload: AuthzDecisionDiagnostic = {
    v: 1,
    ability: 'update',
    allowed: true,
    reason: 'policy',
    userRef: 'User#1',
    resourceType: 'Post',
    resourceId: 7,
    ...over,
  };
  channel.publish(payload);
}

describe('AuthorizationWatcher', () => {
  let cleanup: (() => void) | undefined;
  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
  });

  it('records an allow decision with the right content + tags', async () => {
    const watcher = new AuthorizationWatcher();
    const { recorded } = await collectWatcherEntries(watcher);
    cleanup = () => watcher.cleanup();

    publish({ ability: 'update', allowed: true, reason: 'policy' });

    expect(recorded).toHaveLength(1);
    const input = recorded[0];
    expect(input?.type).toBe('authorization');
    expect(input?.familyHash).toBe('update:allow');
    expect(input?.tags).toEqual([
      'ability:update',
      'decision:allow',
      'reason:policy',
      'resource:Post',
    ]);
    expect(input?.content).toMatchObject<AuthorizationEntryContent>({
      ability: 'update',
      allowed: true,
      reason: 'policy',
      user: 'User#1',
      resource: 'Post#7',
    });
  });

  it('records a deny decision with a `denied` tag', async () => {
    const watcher = new AuthorizationWatcher();
    const { recorded } = await collectWatcherEntries(watcher);
    cleanup = () => watcher.cleanup();

    publish({ ability: 'delete', allowed: false, reason: 'policy-before' });

    const input = recorded[0];
    expect(input?.familyHash).toBe('delete:deny');
    expect(input?.tags).toContain('decision:deny');
    expect(input?.tags).toContain('denied');
    expect((input?.content as AuthorizationEntryContent).allowed).toBe(false);
  });

  it('formats a model-less / anonymous decision', async () => {
    const watcher = new AuthorizationWatcher();
    const { recorded } = await collectWatcherEntries(watcher);
    cleanup = () => watcher.cleanup();

    publish({
      ability: 'access-admin',
      allowed: false,
      reason: 'anonymous',
      userRef: null,
      resourceType: null,
      resourceId: null,
    });

    const content = recorded[0]?.content as AuthorizationEntryContent;
    expect(content.user).toBeNull();
    expect(content.resource).toBeNull();
    expect(recorded[0]?.tags).not.toContain('resource:null');
  });

  it('drops malformed / wrong-version payloads', async () => {
    const watcher = new AuthorizationWatcher();
    const { recorded } = await collectWatcherEntries(watcher);
    cleanup = () => watcher.cleanup();

    channel.publish({ v: 2, ability: 'x', allowed: true });
    channel.publish({ not: 'a decision' });

    expect(recorded).toHaveLength(0);
  });

  it('cleanup() unsubscribes so later decisions are ignored', async () => {
    const watcher = new AuthorizationWatcher();
    const { recorded } = await collectWatcherEntries(watcher);
    watcher.cleanup();

    publish({ ability: 'update' });

    expect(recorded).toHaveLength(0);
  });
});
