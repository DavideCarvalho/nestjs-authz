import type { Resource, User } from './types.js';

/**
 * Optional seam that lets a persisted RBAC layer answer named, model-less abilities.
 *
 * This is the Laravel/spatie `Gate::before` grant: when the current user holds the
 * named permission, the ability is allowed regardless of policies/gates. The core
 * does NOT implement this — `@dudousxd/nestjs-authz-typeorm` (and the other RBAC
 * adapters) provide an implementation and register it under the shared
 * {@link PERMISSION_PROVIDER} token. When no provider is registered the Gate is
 * unaffected.
 *
 * Semantics (grant-only, mirroring `Gate::before`):
 * - `true`  → the user holds the permission → allow (short-circuit).
 * - `false`/`undefined` → the provider does not grant it → fall through to the
 *   normal policy/gate resolution.
 *
 * `userRef` is the current user (whatever the app's auth layer produced; `undefined`
 * when anonymous). `permission` is the ability name passed to `gate.allows(...)`.
 * `resource` is the dispatch target, when one was given; providers MAY ignore it —
 * model-less, named-ability grants (e.g. the typeorm RBAC adapter) do.
 *
 * ## Wildcard / hierarchical permissions
 *
 * To support Laravel/spatie-style wildcard grants (a granted `posts.*` satisfying a
 * check for `posts.update`, or `*` satisfying anything), a provider may ALSO expose
 * {@link PermissionProvider.getPermissions} — the user's full granted permission set.
 * When present, the core applies segment-based wildcard matching against that set
 * (see `permission-matcher.ts`), so wildcard semantics work regardless of adapter
 * and without each adapter re-implementing the matching. `hasPermission` remains the
 * exact-match fast path (and the sole contract for providers that don't list grants).
 */
export interface PermissionProvider {
  hasPermission(
    user: User,
    permission: string,
    resource?: Resource,
  ): boolean | undefined | Promise<boolean | undefined>;
  /**
   * Optional: the full set of permission names granted to `user` (each possibly a
   * wildcard pattern such as `posts.*` or `*`). When implemented, the core matches
   * the checked ability against this set using segment-based wildcard semantics, so
   * a granted `posts.*` satisfies `posts.update`. Return `undefined` to defer to
   * `hasPermission` (e.g. for an anonymous/unmappable user).
   */
  getPermissions?(user: User): Iterable<string> | undefined | Promise<Iterable<string> | undefined>;
}
