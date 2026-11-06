import { Policy } from '@nestjs/authorization';
import { Gate } from '../gate.js';

/**
 * The `Gate`'s string abilities as an official policy: ad-hoc gates from
 * `gate.define()`, named permissions, and `ability` + resource checks through the
 * resource's linked policy.
 *
 * ```ts
 * gate.define('access-admin', (user) => user.isStaff);
 *
 * @Can(GatePolicy, 'allows', ability('access-admin'))
 * ```
 */
@Policy()
export class GatePolicy {
  constructor(private readonly gate: Gate) {}

  allows(user: unknown, ability: string, resource?: object): Promise<boolean> {
    return this.gate.forUser(user).allows(ability, resource);
  }
}
