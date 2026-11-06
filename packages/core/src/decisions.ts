import { AuthorizationEvents } from '@nestjs/authorization';
import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
  type OnModuleDestroy,
  type OnModuleInit,
  Optional,
  type Type,
} from '@nestjs/common';
import type { Observable, Subscription } from 'rxjs';
import { authzDecisionChannel, publishAuthzDecision } from './diagnostics.js';
import { authorizedResource } from './helpers.js';
import { getPolicyResource } from './links.js';
import { routeRequirements } from './official.js';
import { currentUserOf } from './runtime.js';

/**
 * Publishes the official guard's decisions on the `authz:decision` channel, allowed and
 * denied, for Telescope-style watchers (the official package publishes denials only).
 *
 * - Denials: the official `AuthorizationEvents` stream, for events the guard raised
 *   (those with a `handler`). `authorize()` denials come from the `Gate` itself.
 * - Allows: an interceptor, which runs only once every guard let the call through,
 *   publishes one decision per official `@Can()` requirement of the handler.
 *
 * Nothing is computed while the channel has no subscriber.
 */
@Injectable()
export class AuthzDecisionPublisher implements NestInterceptor, OnModuleInit, OnModuleDestroy {
  private subscription: Subscription | undefined;

  constructor(@Optional() private readonly events?: AuthorizationEvents) {}

  onModuleInit(): void {
    this.subscription = this.events?.events$.subscribe((event) => {
      if (event.handler === undefined || event.ability === null) return;
      publishAuthzDecision(event.ability, false, 'route', event.user, firstObject(event.args), {
        policy: event.policy,
        handler: event.handler,
      });
    });
  }

  onModuleDestroy(): void {
    this.subscription?.unsubscribe();
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    if (authzDecisionChannel.hasSubscribers) void this.publishAllows(context);
    return next.handle();
  }

  private async publishAllows(context: ExecutionContext): Promise<void> {
    try {
      const type = context.getClass() as Type<unknown>;
      const handler = context.getHandler();
      const requirements = routeRequirements(type, handler);
      if (requirements.length === 0) return;
      const user = await currentUserOf(context);
      for (const { policy, ability } of requirements) {
        const linked = getPolicyResource(policy);
        const resource = linked ? authorizedResource(context, linked) : undefined;
        publishAuthzDecision(ability, true, 'route', user, resource as object | undefined, {
          policy: policy.name,
          handler: `${type.name}.${handler.name}`,
        });
      }
    } catch {
      // Observability never breaks a request.
    }
  }
}

function firstObject(args: readonly unknown[]): object | undefined {
  const first = args[0];
  return first !== null && typeof first === 'object' ? first : undefined;
}
