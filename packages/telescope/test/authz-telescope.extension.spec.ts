import {
  type Entry,
  type ExtensionContext,
  InMemoryStorageProvider,
  TELESCOPE_STORAGE,
  resolveConfig,
} from '@dudousxd/nestjs-telescope';
import { describe, expect, it } from 'vitest';
import {
  AUTHORIZATION_ENTRY_TYPE,
  type AuthorizationEntryContent,
} from '../src/authorization.watcher.js';
import { nestjsAuthzTelescope } from '../src/authz-telescope.extension.js';

let seq = 0;

/** Build a stored `authorization` Entry from a decision content. */
function authzEntry(content: AuthorizationEntryContent): Entry<AuthorizationEntryContent> {
  const n = seq++;
  return {
    id: `e${n}`,
    batchId: 'b',
    type: AUTHORIZATION_ENTRY_TYPE,
    familyHash: `${content.ability}:${content.allowed ? 'allow' : 'deny'}`,
    content,
    tags: [
      `ability:${content.ability}`,
      `decision:${content.allowed ? 'allow' : 'deny'}`,
      ...(content.allowed ? [] : ['denied']),
    ],
    sequence: n,
    durationMs: null,
    origin: 'http',
    instanceId: 'i',
    traceId: null,
    spanId: null,
    createdAt: new Date(2026, 0, 1, 0, 0, n),
  };
}

async function makeCtx(): Promise<{ ctx: ExtensionContext; storage: InMemoryStorageProvider }> {
  const storage = new InMemoryStorageProvider();
  const ctx: ExtensionContext = {
    config: resolveConfig({}),
    moduleRef: {
      get: (token: unknown) => {
        if (token === TELESCOPE_STORAGE) return storage;
        throw new Error('unknown token');
      },
    } as unknown as ExtensionContext['moduleRef'],
  };
  return { ctx, storage };
}

describe('nestjsAuthzTelescope extension', () => {
  it('contributes a watcher, entry type, dashboard and providers', () => {
    const ext = nestjsAuthzTelescope();
    expect(ext.name).toBe('nestjs-authz');

    const fakeCtx = {} as ExtensionContext;
    expect(ext.watchers?.(fakeCtx).map((w) => w.type)).toEqual(['authorization']);
    expect(ext.entryTypes?.(fakeCtx)).toEqual([
      { id: 'authorization', label: 'Authorization', dot: 'bg-amber-400' },
    ]);

    const dashboards = ext.dashboards?.(fakeCtx) ?? [];
    expect(dashboards.map((d) => d.id)).toEqual(['authz.authorization']);
    expect(dashboards[0]?.panels.map((p) => p.kind)).toEqual(['topN', 'table']);

    expect(ext.dataProviders?.(fakeCtx).map((p) => p.name)).toEqual([
      'authz.deniedAbilities',
      'authz.recentDecisions',
    ]);
  });

  it('deniedAbilities provider ranks denied abilities by count', async () => {
    const { ctx, storage } = await makeCtx();
    await storage.store([
      authzEntry({
        ability: 'update',
        allowed: false,
        reason: 'policy',
        user: 'User#1',
        resource: 'Post#1',
      }),
      authzEntry({
        ability: 'update',
        allowed: false,
        reason: 'policy',
        user: 'User#2',
        resource: 'Post#2',
      }),
      authzEntry({
        ability: 'delete',
        allowed: false,
        reason: 'policy',
        user: 'User#1',
        resource: 'Post#1',
      }),
      authzEntry({
        ability: 'update',
        allowed: true,
        reason: 'policy',
        user: 'User#3',
        resource: 'Post#3',
      }),
    ]);

    const provider = nestjsAuthzTelescope()
      .dataProviders?.(ctx)
      .find((p) => p.name === 'authz.deniedAbilities');
    const result = (await provider?.resolve({}, ctx)) as {
      items: { label: string; value: number }[];
    };

    expect(result.items).toEqual([
      { label: 'update', value: 2 },
      { label: 'delete', value: 1 },
    ]);
  });

  it('recentDecisions provider returns a table row per decision', async () => {
    const { ctx, storage } = await makeCtx();
    await storage.store([
      authzEntry({
        ability: 'publish',
        allowed: false,
        reason: 'gate',
        user: 'User#9',
        resource: null,
      }),
    ]);

    const provider = nestjsAuthzTelescope()
      .dataProviders?.(ctx)
      .find((p) => p.name === 'authz.recentDecisions');
    const result = (await provider?.resolve({}, ctx)) as { rows: Record<string, unknown>[] };

    expect(result.rows).toEqual([
      { ability: 'publish', decision: 'deny', reason: 'gate', user: 'User#9', resource: null },
    ]);
  });
});
