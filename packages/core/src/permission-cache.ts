import { permissionSatisfied } from './permission-matcher.js';
import type { PermissionProvider } from './permission-provider.js';
import type { User } from './types.js';

/**
 * A memo over a {@link PermissionProvider}'s `getPermissions(user)` so a user's
 * granted-permission set is fetched AT MOST ONCE per logical scope (a single
 * `allowsMany` batch, or — when wired to nestjs-context — a single HTTP request).
 *
 * Without it, every `gate.allows(...)` re-fetches the set (an N+1 within a list
 * page, since each card runs its own check). The cache keys by the resolved
 * `user` identity so two checks for the SAME user share one fetch while a
 * different user still triggers its own.
 *
 * Only the `getPermissions` (full-set, wildcard-matched) path is memoized — the
 * exact-match `hasPermission` fast path is left to the provider, which is free to
 * memoize internally. A provider WITHOUT `getPermissions` makes this a no-op.
 */
export class PermissionCache {
  // Keyed by the user object identity. `Map` (not WeakMap) because a batch/request
  // cache is short-lived and we also accept primitive ids/refs as keys.
  private readonly byUser = new Map<unknown, Promise<ReadonlySet<string> | undefined>>();

  /**
   * Resolve the user's granted-permission set via the provider, memoized for the
   * cache's lifetime. Returns `undefined` when the provider can't list grants
   * (no `getPermissions`, or it yielded nullish) so the caller falls back to the
   * exact-match `hasPermission` path.
   */
  async getPermissions(
    provider: PermissionProvider,
    user: User,
  ): Promise<ReadonlySet<string> | undefined> {
    if (typeof provider.getPermissions !== 'function') return undefined;
    const cached = this.byUser.get(user);
    if (cached) return cached;
    const pending = Promise.resolve(provider.getPermissions(user)).then((granted) =>
      granted == null ? undefined : new Set(granted),
    );
    this.byUser.set(user, pending);
    return pending;
  }

  /**
   * True when the user's (memoized) granted set satisfies `ability` under the
   * core's wildcard matcher. `undefined` when no set is available (caller should
   * defer to `hasPermission`).
   */
  async satisfies(
    provider: PermissionProvider,
    user: User,
    ability: string,
  ): Promise<boolean | undefined> {
    const set = await this.getPermissions(provider, user);
    if (set === undefined) return undefined;
    return permissionSatisfied(set, ability);
  }
}
