import { Body, Controller, type Type } from '@nestjs/common';
import { Post as HttpPost } from '@nestjs/common';
import { Gate } from './gate.js';

/**
 * Request body for the fallback `can` endpoint. Mirrors the payload emitted by
 * the codegen `can()` helper: `{ ability, resource?: { type, id } | null }`.
 */
export interface CanRequestBody {
  ability: string;
  resource?: { type: string; id?: string | number } | null;
}

/** Response shape: a single boolean verdict. */
export interface CanResponseBody {
  allowed: boolean;
}

/**
 * Build the opt-in fallback controller class, mounted at `path`. Kept as a
 * factory so the route path is configurable via `AuthzModule.forRoot({ canEndpoint })`.
 *
 * The endpoint runs `gate.allows(ability, resource?)` for the CURRENT (context)
 * user.
 *
 * LIMITATION — read this before relying on the fallback for resource decisions:
 * the `{ type, id }` resource shim is forwarded as-is and NEVER matches a
 * registered `@Policy` by constructor, so this endpoint can ONLY resolve
 * class-level abilities and ad-hoc gates. Per-instance decisions MUST be
 * hydrated via shared props / `authorizeResource` (tiers 1-2); a resource-bound
 * ability that misses the client cache and falls through to `POST /authz/can`
 * will DENY. An unresolved ability is likewise treated as a deny (never a 500).
 */
export function createCanController(path: string): Type<unknown> {
  @Controller(path)
  class AuthzCanController {
    constructor(private readonly gate: Gate) {}

    @HttpPost()
    async can(@Body() body: CanRequestBody): Promise<CanResponseBody> {
      const ability = body?.ability;
      if (typeof ability !== 'string' || ability.length === 0) {
        return { allowed: false };
      }
      const resource = body?.resource ?? undefined;
      try {
        const allowed = await this.gate.allows(
          ability,
          resource == null ? undefined : (resource as object),
        );
        return { allowed };
      } catch {
        // Unresolved/ambiguous ability — fail closed.
        return { allowed: false };
      }
    }
  }

  return AuthzCanController;
}

/** Default mount path for the fallback endpoint (matches codegen's `/authz/can`). */
export const DEFAULT_CAN_ENDPOINT_PATH = 'authz/can';
