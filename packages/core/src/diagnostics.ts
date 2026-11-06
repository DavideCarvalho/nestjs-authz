import { emit, getChannel } from '@dudousxd/nestjs-diagnostics';
import type { Resource, User } from './types.js';

/**
 * The standard `aviary:` channel this library emits on, via the shared
 * `@dudousxd/nestjs-diagnostics` convention. The generic
 * `@dudousxd/nestjs-diagnostics-telescope` watcher records every decision with no
 * authz-specific watcher needed. `getChannel` also registers the name so that
 * generic observer can discover it. Read `.hasSubscribers` to gate work before
 * building a payload — when nothing subscribes (the common case) emitting a
 * decision is effectively free.
 */
export const authzDecisionChannel = getChannel('authz', 'decision');

/**
 * Every authorization decision, allowed or denied: each `Gate` check, and each official
 * `@Can()` requirement the guard enforced (`reason: 'route'`). The official package
 * publishes only denials, on `nestjs:authorization:denied`; this channel carries both,
 * for Telescope-style watchers.
 */
export interface AuthzDecisionDiagnostic {
  v: 1;
  /** The ability checked, e.g. `'update'` or `'access-admin'`. */
  ability: string;
  /** The verdict — `true` allow, `false` deny. */
  allowed: boolean;
  /** Which resolution path decided it (see {@link AuthzDecisionReason}). */
  reason: AuthzDecisionReason;
  /** The official policy class that decided, e.g. `'PostPolicy'`, or `null` when none did. */
  policy: string | null;
  /** The handler the official guard checked (`Class.method`), or `null` for a `Gate` call. */
  handler: string | null;
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
  | 'decision-provider'
  | 'permission-provider'
  | 'policy'
  | 'gate'
  | 'anonymous'
  | 'route';

/** Where a decision came from, beyond the verdict. */
export interface AuthzDecisionSource {
  policy?: string | null;
  handler?: string | null;
}

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
  source: AuthzDecisionSource = {},
): void {
  if (!authzDecisionChannel.hasSubscribers) return;
  const payload: AuthzDecisionDiagnostic = {
    v: 1,
    ability,
    allowed,
    reason,
    policy: source.policy ?? null,
    handler: source.handler ?? null,
    userRef: labelUser(user),
    resourceType: resourceType(resource),
    resourceId: resourceId(resource),
  };
  // `emit` builds the `aviary:authz:decision` envelope, auto-fills `traceId` from
  // the optional context accessor, re-checks `hasSubscribers`, and never throws.
  emit('authz', 'decision', payload);
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
