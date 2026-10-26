import { CompiledPermissions } from './permission-matcher.js';
import type { PermissionProvider } from './permission-provider.js';
import type { RoleProvider } from './role-provider.js';
import type { User } from './types.js';

/** A distinct number per user class, so two classes that share a name never share a key. */
const classIds = new WeakMap<object, number>();
let nextClassId = 0;

function classIdOf(ctor: object): number {
  let id = classIds.get(ctor);
  if (id === undefined) {
    id = nextClassId++;
    classIds.set(ctor, id);
  }
  return id;
}

/**
 * The string identity of a user object that names its row, or `undefined` when it
 * doesn't. A string/number `id` names a row when the object also says what kind of
 * row it is: a string `type`, or a class of its own (an ORM entity). Two
 * separately-loaded copies of that row (an ORM without an identity map, or a
 * re-hydrated user) then share one entry. A plain object without `type` names
 * nothing beyond itself (a human user and a service account may both be `{ id: 1 }`),
 * so it keys by identity.
 */
function rowKey(user: object): string | undefined {
  const { type, id } = user as { type?: unknown; id?: unknown };
  if (typeof id !== 'string' && typeof id !== 'number') return undefined;
  const proto = Object.getPrototypeOf(user) as { constructor?: unknown } | null;
  const plain = proto === null || proto === Object.prototype;
  if (plain && typeof type !== 'string') return undefined;
  const ctor = proto?.constructor;
  const kind = typeof ctor === 'function' ? classIdOf(ctor) : -1;
  return JSON.stringify([kind, typeof type === 'string' ? type : null, typeof id, id]);
}

/**
 * A memo over a {@link PermissionProvider}'s `getPermissions(user)` and a
 * {@link RoleProvider}'s `getRoles(user)` so each is fetched AT MOST ONCE per
 * logical scope (a single `allowsMany` batch, or — when wired to nestjs-context —
 * a single HTTP request).
 *
 * Without it, every `gate.allows(...)` re-fetches the set (an N+1 within a list
 * page, since each card runs its own check). Entries are keyed by the row a user
 * names (see {@link rowKey}), else by identity, so checks for the SAME user share
 * one fetch while a different user still triggers its own. The granted set is
 * compiled once per entry, so each check is a hash lookup plus a scan of the
 * wildcard grants only.
 *
 * A grant or revocation made while the scope is alive is seen by the next scope
 * (the next request), not by later checks in the same one.
 */
export class PermissionCache {
  // `Map` (not WeakMap) because a batch/request cache is short-lived and keys are
  // strings or primitive ids as often as objects.
  private readonly byUser = new Map<unknown, Promise<CompiledPermissions | undefined>>();
  private readonly rolesByUser = new Map<unknown, Promise<string[] | undefined>>();
  // One token object per row key, so a string row key can never equal a bare-id user.
  private readonly rowTokens = new Map<string, object>();

  private userCacheKey(user: User): unknown {
    if (user === null || typeof user !== 'object') return user;
    const row = rowKey(user);
    if (row === undefined) return user;
    let token = this.rowTokens.get(row);
    if (!token) {
      token = {};
      this.rowTokens.set(row, token);
    }
    return token;
  }

  private compiled(
    provider: PermissionProvider,
    user: User,
  ): Promise<CompiledPermissions | undefined> | undefined {
    if (typeof provider.getPermissions !== 'function') return undefined;
    const key = this.userCacheKey(user);
    const cached = this.byUser.get(key);
    if (cached) return cached;
    const pending = Promise.resolve(provider.getPermissions(user)).then((granted) =>
      granted == null ? undefined : new CompiledPermissions(granted),
    );
    this.byUser.set(key, pending);
    pending.catch(() => this.byUser.delete(key));
    return pending;
  }

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
    return (await this.compiled(provider, user))?.granted;
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
    return (await this.compiled(provider, user))?.satisfies(ability);
  }

  /** The user's roles from `provider`, memoized for the cache's lifetime. */
  getRoles(provider: RoleProvider, user: User): Promise<string[] | undefined> {
    const key = this.userCacheKey(user);
    const cached = this.rolesByUser.get(key);
    if (cached) return cached;
    const pending = Promise.resolve(provider.getRoles(user));
    this.rolesByUser.set(key, pending);
    pending.catch(() => this.rolesByUser.delete(key));
    return pending;
  }
}
