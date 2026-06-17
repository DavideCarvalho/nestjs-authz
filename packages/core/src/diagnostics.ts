import diagnostics_channel from 'node:diagnostics_channel';
import type { Resource, User } from './types.js';

/**
 * Channel name — the cross-repo wire contract with `@dudousxd/nestjs-authz-telescope`'s
 * authorization watcher (and any other observer). Versioned by the payload's `v` field,
 * not by name. Keep this string byte-identical on both sides.
 */
export const AUTHZ_DECISION_CHANNEL = 'nestjs-authz:decision';

/**
 * Memoized by Node: the same channel object is returned for the same name. Read
 * `.hasSubscribers` to gate any work before publishing — when nothing subscribes
 * (the common case) emitting a decision is effectively free.
 */
export const authzDecisionChannel = diagnostics_channel.channel(AUTHZ_DECISION_CHANNEL);

/**
 * Every authorization decision the {@link Gate} reaches, published once per
 * `allows`/`authorize`/`denies` call. `reason` names which resolution path
 * produced the verdict so a 403 is debuggable.
 */
export interface AuthzDecisionDiagnostic {
  v: 1;
  /** The ability checked, e.g. `'update'` or `'access-admin'`. */
  ability: string;
  /** The verdict — `true` allow, `false` deny. */
  allowed: boolean;
  /** Which resolution path decided it (see {@link AuthzDecisionReason}). */
  reason: AuthzDecisionReason;
  /** A label for the resolved user (`<type>#<id>` / constructor name), or `null` when anonymous. */
  userRef: string | null;
  /** The resource class name the ability targeted, or `null` for a model-less ability. */
  resourceType: string | null;
  /** The resource's `id` when discoverable on the instance, else `null`. */
  resourceId: string | number | null;
}

/** The resolution path that produced a decision — the "why" behind a 403 (or a grant). */
export type AuthzDecisionReason =
  | 'super-admin'
  | 'permission-provider'
  | 'policy-before'
  | 'policy'
  | 'gate'
  | 'anonymous';

/**
 * Publish a decision to the channel, but only when something is listening. Never
 * throws — building the payload or notifying a subscriber must not break a check.
 */
export function publishAuthzDecision(
  ability: string,
  allowed: boolean,
  reason: AuthzDecisionReason,
  user: User,
  resource: Resource | undefined,
): void {
  if (!authzDecisionChannel.hasSubscribers) return;
  try {
    const payload: AuthzDecisionDiagnostic = {
      v: 1,
      ability,
      allowed,
      reason,
      userRef: labelUser(user),
      resourceType: resourceType(resource),
      resourceId: resourceId(resource),
    };
    authzDecisionChannel.publish(payload);
  } catch {
    // Observability must never break authorization.
  }
}

/** A short, JSON-safe label for the user — `<type>#<id>`, a constructor name, or `null`. */
function labelUser(user: User): string | null {
  if (user == null) return null;
  if (typeof user === 'object') {
    const obj = user as Record<string, unknown>;
    const type = (obj.type ?? obj.constructor?.name) as string | undefined;
    const id = obj.id;
    if (type && (typeof id === 'string' || typeof id === 'number')) return `${type}#${id}`;
    if (typeof obj.id === 'string' || typeof obj.id === 'number') return String(obj.id);
    return obj.constructor?.name ?? null;
  }
  return String(user);
}

/** The resource's class name (`Post`), or `null` when model-less. A class itself maps to its name. */
function resourceType(resource: Resource | undefined): string | null {
  if (resource == null) return null;
  if (typeof resource === 'function') return (resource as { name?: string }).name ?? null;
  return (resource as { constructor?: { name?: string } }).constructor?.name ?? null;
}

/** The resource instance's `id`, when present and primitive; otherwise `null`. */
function resourceId(resource: Resource | undefined): string | number | null {
  if (resource == null || typeof resource === 'function') return null;
  const id = (resource as Record<string, unknown>).id;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
}
