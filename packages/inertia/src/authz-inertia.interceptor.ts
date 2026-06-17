import { Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import {
  type CallHandler,
  type ExecutionContext,
  Inject,
  Injectable,
  type NestInterceptor,
  Optional,
} from '@nestjs/common';
import type { Observable } from 'rxjs';
import { from, switchMap } from 'rxjs';
import { resolveClassAbilities } from './resolve-abilities.js';
import { DEFAULT_PROP_KEY } from './share.js';
import { AUTHZ_INERTIA_OPTIONS } from './tokens.js';
import type { AuthzInertiaOptions, RequestWithInertia } from './types.js';

/**
 * Auto-shares the current user's class-level abilities into `props.<propKey>.can`
 * for every HTTP request that carries an attached Inertia service (`req.inertia`),
 * by calling `req.inertia.share(...)` BEFORE the route handler renders.
 *
 * No network request: abilities are resolved by direct `gate.allows` calls.
 * Non-HTTP contexts and requests without `req.inertia` are passed through untouched.
 */
@Injectable()
export class AuthzInertiaInterceptor implements NestInterceptor {
  private readonly propKey: string;

  constructor(
    private readonly gate: Gate,
    private readonly policies: PolicyRegistry,
    @Optional()
    @Inject(AUTHZ_INERTIA_OPTIONS)
    private readonly options: AuthzInertiaOptions = {},
  ) {
    this.propKey = options?.propKey ?? DEFAULT_PROP_KEY;
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (context.getType() !== 'http') return next.handle();
    const req = context.switchToHttp().getRequest<RequestWithInertia>();
    const inertia = req?.inertia;
    if (!inertia || typeof inertia.share !== 'function') return next.handle();

    return from(
      resolveClassAbilities(this.gate, this.policies, {
        ...(this.options.abilities !== undefined ? { abilities: this.options.abilities } : {}),
        ...(this.options.abilityNamer !== undefined
          ? { abilityNamer: this.options.abilityNamer }
          : {}),
        ...(this.options.includeBareMethodNames !== undefined
          ? { includeBareMethodNames: this.options.includeBareMethodNames }
          : {}),
      }),
    ).pipe(
      switchMap((can) => {
        inertia.share({ [this.propKey]: { can } });
        return next.handle();
      }),
    );
  }
}
