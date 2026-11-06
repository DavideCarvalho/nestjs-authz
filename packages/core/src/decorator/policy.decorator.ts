import type { Type } from '@nestjs/common';
import { PolicyFor } from '../links.js';

/**
 * @deprecated Use the official `@Policy()` from `@nestjs/authorization`, plus
 * `@PolicyFor(Resource)` when the extras need the resource link (`gate.allows('update',
 * post)`, `gate.scope(Post)`, the deprecated string `@Can`). Same as `@PolicyFor(resource)`.
 */
export function Policy(resource: Type<unknown>): ClassDecorator {
  return PolicyFor(resource);
}
