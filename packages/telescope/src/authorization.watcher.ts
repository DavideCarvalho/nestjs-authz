import diagnostics_channel from 'node:diagnostics_channel';
import type { AuthzDecisionDiagnostic } from '@dudousxd/nestjs-authz';
import type { RecordInput, Watcher, WatcherContext } from '@dudousxd/nestjs-telescope';

/**
 * The channel name is the cross-repo contract with `@dudousxd/nestjs-authz`
 * (exported there as `AUTHZ_DECISION_CHANNEL`). Hardcoded here so the watcher
 * never needs `@dudousxd/nestjs-authz` at runtime — keep it byte-identical on
 * both sides. Versioned by the payload's `v` field, not by name.
 */
const AUTHZ_DECISION_CHANNEL = 'nestjs-authz:decision';

/** Telescope entry `type` produced by this watcher. */
export const AUTHORIZATION_ENTRY_TYPE = 'authorization';

/** What a single recorded authorization entry looks like in the Telescope dashboard. */
export interface AuthorizationEntryContent {
  /** The ability checked, e.g. `'update'`. */
  ability: string;
  /** The verdict — `true` allow, `false` deny. */
  allowed: boolean;
  /** Which resolution path produced the verdict (super-admin, policy, gate, …). */
  reason: string;
  /** A label for the resolved user (`<type>#<id>` / id / class name), or `null` when anonymous. */
  user: string | null;
  /** The resource the ability targeted (`<type>#<id>` / `<type>`), or `null` for a model-less ability. */
  resource: string | null;
}

/**
 * One-time guard so an unsupported producer version (`v !== 1`) is surfaced once
 * per process instead of on every decision.
 */
let warnedUnsupportedVersion = false;

/**
 * A nestjs-telescope watcher that records every authorization decision the
 * `@dudousxd/nestjs-authz` `Gate` reaches as one `authorization` entry, so a 403
 * is debuggable (which ability, allow vs deny, which path decided it, for whom).
 *
 * ## How it works
 * On `register` the watcher subscribes a listener to the `nestjs-authz:decision`
 * diagnostics channel. The Gate publishes synchronously inside `allows()` /
 * `authorize()`, so the listener runs on the same async context as the check —
 * `ctx.record(...)` lands in the request's batch. Subscribing also flips the
 * producer's `channel.hasSubscribers` to `true`, which is what makes the Gate
 * start building + publishing payloads at all (zero-overhead when nobody listens).
 *
 * ```ts
 * TelescopeModule.forRoot({ extensions: [nestjsAuthzTelescope()] });
 * ```
 */
export class AuthorizationWatcher implements Watcher {
  readonly type = AUTHORIZATION_ENTRY_TYPE;
  private registered = false;
  private onMessage: ((msg: unknown) => void) | null = null;

  register(ctx: WatcherContext): void {
    if (this.registered) return;
    this.registered = true;

    const channel = diagnostics_channel.channel(AUTHZ_DECISION_CHANNEL);
    this.onMessage = (msg) => this.safeRecord(ctx, msg);
    channel.subscribe(this.onMessage);
  }

  /** Unsubscribe the listener. Safe to call when never registered. */
  cleanup(): void {
    if (this.onMessage) {
      diagnostics_channel.channel(AUTHZ_DECISION_CHANNEL).unsubscribe(this.onMessage);
      this.onMessage = null;
    }
    this.registered = false;
  }

  /** Validate + record, swallowing any failure so an authorization check can never break. */
  private safeRecord(ctx: WatcherContext, msg: unknown): void {
    try {
      if (!isAuthzDecision(msg)) {
        if (!warnedUnsupportedVersion && isAuthzShaped(msg)) {
          warnedUnsupportedVersion = true;
          console.warn(
            `AuthorizationWatcher: dropping unsupported diagnostic version v=${(msg as { v?: unknown }).v} (expected 1) — upgrade @dudousxd/nestjs-authz-telescope to match @dudousxd/nestjs-authz`,
          );
        }
        return;
      }
      ctx.record(buildAuthorizationEntry(msg));
    } catch (err) {
      // NOT rethrown — telescope must never break an authorization check.
      console.error('AuthorizationWatcher: failed to record authorization decision:', err);
    }
  }
}

/** Map a decision payload to a Telescope `RecordInput`. */
export function buildAuthorizationEntry(
  msg: AuthzDecisionDiagnostic,
): RecordInput<AuthorizationEntryContent> {
  const resource = formatResource(msg.resourceType, msg.resourceId);
  const content: AuthorizationEntryContent = {
    ability: msg.ability,
    allowed: msg.allowed,
    reason: msg.reason,
    user: msg.userRef ?? null,
    resource,
  };
  return {
    type: AUTHORIZATION_ENTRY_TYPE,
    // Group by ability + verdict so the dashboard can roll up "denied: update" etc.
    familyHash: `${msg.ability}:${msg.allowed ? 'allow' : 'deny'}`,
    tags: [
      `ability:${msg.ability}`,
      `decision:${msg.allowed ? 'allow' : 'deny'}`,
      `reason:${msg.reason}`,
      ...(msg.resourceType ? [`resource:${msg.resourceType}`] : []),
      ...(msg.allowed ? [] : ['denied']),
    ],
    content,
  };
}

function formatResource(type: string | null, id: string | number | null): string | null {
  if (!type) return null;
  return id == null ? type : `${type}#${id}`;
}

/** Loose structural check — does this look like an authz decision payload at all? */
export function isAuthzShaped(
  msg: unknown,
): msg is { v: unknown; ability: unknown; allowed: unknown } {
  return (
    typeof msg === 'object' && msg !== null && 'v' in msg && 'ability' in msg && 'allowed' in msg
  );
}

/** Strict, version-pinned validation of a v1 decision payload. */
export function isAuthzDecision(msg: unknown): msg is AuthzDecisionDiagnostic {
  if (!isAuthzShaped(msg)) return false;
  const m = msg as Record<string, unknown>;
  return (
    m.v === 1 &&
    typeof m.ability === 'string' &&
    typeof m.allowed === 'boolean' &&
    typeof m.reason === 'string'
  );
}
