import {
  type DashboardSpec,
  type DataProvider,
  type Entry,
  type ExtensionContext,
  type ExtensionEntryType,
  type StorageProvider,
  TELESCOPE_STORAGE,
  type TelescopeExtension,
  type Watcher,
} from '@dudousxd/nestjs-telescope';
import {
  AUTHORIZATION_ENTRY_TYPE,
  type AuthorizationEntryContent,
  AuthorizationWatcher,
} from './authorization.watcher.js';

/** Provider names the dashboard panels bind to (namespaced to avoid collisions). */
const DENIED_ABILITIES_PROVIDER = 'authz.deniedAbilities';
const RECENT_DECISIONS_PROVIDER = 'authz.recentDecisions';

/** Options for {@link nestjsAuthzTelescope}. */
export interface AuthzTelescopeOptions {
  /** How many denied abilities to surface in the top-N panel. Default 10. */
  topDeniedLimit?: number;
  /** How many recent decisions to list in the table panel. Default 50. */
  recentLimit?: number;
}

/**
 * A `@dudousxd/nestjs-telescope` extension that records every authorization
 * decision the `@dudousxd/nestjs-authz` `Gate` reaches — so a 403 is debuggable.
 *
 * It wires four hooks:
 *  - `watchers`     — an {@link AuthorizationWatcher} subscribing to the
 *    `nestjs-authz:decision` diagnostics channel, recording one `authorization`
 *    entry per decision.
 *  - `entryTypes`   — registers the navigable `authorization` type (amber dot).
 *  - `dashboards`   — an "Authorization" page with a top-N of denied abilities and
 *    a table of the most recent decisions.
 *  - `dataProviders`— the server-side queries the two panels bind to, reading the
 *    Telescope store directly.
 *
 * ```ts
 * TelescopeModule.forRoot({ extensions: [nestjsAuthzTelescope()] });
 * ```
 */
export function nestjsAuthzTelescope(options: AuthzTelescopeOptions = {}): TelescopeExtension {
  const topDeniedLimit = options.topDeniedLimit ?? 10;
  const recentLimit = options.recentLimit ?? 50;

  return {
    name: 'nestjs-authz',

    watchers(): Watcher[] {
      return [new AuthorizationWatcher()];
    },

    entryTypes(): ExtensionEntryType[] {
      return [{ id: AUTHORIZATION_ENTRY_TYPE, label: 'Authorization', dot: 'bg-amber-400' }];
    },

    dashboards(): DashboardSpec[] {
      return [
        {
          id: 'authz.authorization',
          label: 'Authorization',
          navGroup: 'Security',
          panels: [
            {
              kind: 'topN',
              title: 'Most denied abilities',
              data: { provider: DENIED_ABILITIES_PROVIDER, query: { limit: topDeniedLimit } },
              limit: topDeniedLimit,
            },
            {
              kind: 'table',
              title: 'Recent decisions',
              data: { provider: RECENT_DECISIONS_PROVIDER, query: { limit: recentLimit } },
              columns: [
                { key: 'ability', label: 'Ability' },
                { key: 'decision', label: 'Decision' },
                { key: 'reason', label: 'Reason' },
                { key: 'user', label: 'User' },
                { key: 'resource', label: 'Resource' },
              ],
            },
          ],
        },
      ];
    },

    dataProviders(): DataProvider[] {
      return [
        {
          name: DENIED_ABILITIES_PROVIDER,
          async resolve(query, ctx) {
            const limit = numberOr(query?.limit, topDeniedLimit);
            const entries = await loadDecisions(ctx, 'denied');
            const counts = new Map<string, number>();
            for (const entry of entries) {
              const content = entry.content as AuthorizationEntryContent | null;
              if (!content || content.allowed) continue;
              counts.set(content.ability, (counts.get(content.ability) ?? 0) + 1);
            }
            const items = [...counts.entries()]
              .map(([label, value]) => ({ label, value }))
              .sort((a, b) => b.value - a.value)
              .slice(0, limit);
            return { items };
          },
        },
        {
          name: RECENT_DECISIONS_PROVIDER,
          async resolve(query, ctx) {
            const limit = numberOr(query?.limit, recentLimit);
            const entries = await loadDecisions(ctx, undefined, limit);
            const rows = entries.map((entry) => {
              const content = entry.content as AuthorizationEntryContent | null;
              return {
                ability: content?.ability ?? null,
                decision: content?.allowed ? 'allow' : 'deny',
                reason: content?.reason ?? null,
                user: content?.user ?? null,
                resource: content?.resource ?? null,
              };
            });
            return { rows };
          },
        },
      ];
    },
  };
}

/** Resolve the Telescope store and fetch `authorization` entries (optionally tag-filtered). */
async function loadDecisions(ctx: ExtensionContext, tag?: string, limit = 200): Promise<Entry[]> {
  const storage = ctx.moduleRef.get<StorageProvider>(TELESCOPE_STORAGE, { strict: false });
  const page = await storage.get({
    type: AUTHORIZATION_ENTRY_TYPE,
    ...(tag ? { tag } : {}),
    limit,
  });
  return page.data;
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

export default nestjsAuthzTelescope;
