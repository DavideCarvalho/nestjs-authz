import 'reflect-metadata';
import type { ExecutionContext } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { PolicyNotDecoratedException } from '../src/errors/exceptions.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import { IdParamResourceResolver } from '../src/resource-resolver.js';

class Widget {
  id!: string;
}

function ctxWithParams(params: Record<string, unknown>): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ params }) }),
  } as unknown as ExecutionContext;
}

describe('IdParamResourceResolver', () => {
  it('builds an instance keyed by the route :id param', () => {
    const resolver = new IdParamResourceResolver();
    const instance = resolver.resolve(Widget, ctxWithParams({ id: 'abc' }));
    expect(instance).toBeInstanceOf(Widget);
    expect((instance as Widget).id).toBe('abc');
  });

  it('returns undefined when the param is absent', () => {
    const resolver = new IdParamResourceResolver();
    expect(resolver.resolve(Widget, ctxWithParams({}))).toBeUndefined();
  });

  it('honors a custom param name', () => {
    const resolver = new IdParamResourceResolver('widgetId');
    const instance = resolver.resolve(Widget, ctxWithParams({ widgetId: '9' }));
    expect((instance as Widget).id).toBe('9');
  });
});

describe('PolicyRegistry', () => {
  it('throws when registering an undecorated policy', () => {
    class NotAPolicy {}
    const registry = new PolicyRegistry();
    expect(() => registry.register(new NotAPolicy())).toThrow(PolicyNotDecoratedException);
  });
});
