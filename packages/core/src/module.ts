import {
  type DynamicModule,
  Inject,
  Injectable,
  Module,
  type OnModuleInit,
  Optional,
  type Provider,
  type Type,
} from '@nestjs/common';
import { APP_GUARD, DiscoveryModule, DiscoveryService, ModuleRef } from '@nestjs/core';
import { DEFAULT_CAN_ENDPOINT_PATH, createCanController } from './can-endpoint.controller.js';
import { getPolicyResource } from './decorator/policy.decorator.js';
import { Gate } from './gate.js';
import { CanGuard } from './guard/can.guard.js';
import { RolesGuard } from './guard/roles.guard.js';
import { PolicyRegistry } from './policy-registry.js';
import { IdParamResourceResolver, type ResourceResolver } from './resource-resolver.js';
import { AUTHZ_MODULE_OPTIONS, RESOURCE_HYDRATOR, RESOURCE_RESOLVER } from './tokens.js';
import type {
  AuthzModuleAsyncOptions,
  AuthzModuleOptions,
  AuthzModuleOptionsFactory,
  PolicyInstance,
  ResourceLoaderMap,
} from './types.js';

/**
 * Populates the {@link PolicyRegistry} at boot from explicit `policies: []` and
 * auto-discovered `@Policy`-decorated providers.
 *
 * Explicit policies are read from the RESOLVED {@link AUTHZ_MODULE_OPTIONS} (so a
 * `forRootAsync` `useFactory`/`useClass` that returns `policies: [...]` registers
 * them too) and resolved as provider instances via {@link ModuleRef}.
 */
@Injectable()
class AuthzPolicyBootstrap implements OnModuleInit {
  constructor(
    private readonly registry: PolicyRegistry,
    private readonly discovery: DiscoveryService,
    private readonly moduleRef: ModuleRef,
    @Optional() @Inject(AUTHZ_MODULE_OPTIONS) private readonly options?: AuthzModuleOptions,
  ) {}

  async onModuleInit(): Promise<void> {
    const seen = new Set<unknown>();

    // 1. Explicit `policies: []` from resolved options (forRoot AND forRootAsync).
    for (const PolicyClass of this.options?.policies ?? []) {
      if (seen.has(PolicyClass)) continue;
      const instance = await this.resolvePolicyInstance(PolicyClass);
      if (instance) {
        seen.add(PolicyClass);
        this.registry.register(instance);
      }
    }

    // 2. Auto-discovered @Policy-decorated providers.
    for (const wrapper of this.discovery.getProviders()) {
      const instance = wrapper.instance as PolicyInstance | undefined;
      if (!instance || typeof instance !== 'object') continue;
      const ctor = instance.constructor;
      if (!ctor || seen.has(ctor)) continue;
      if (getPolicyResource(instance)) {
        seen.add(ctor);
        this.registry.register(instance);
      }
    }
  }

  /**
   * Resolve a policy class to an instance. Prefers an existing provider (so DI
   * deps are honored); falls back to instantiating it through the container when
   * the class was passed via `forRootAsync` options but not registered as a
   * provider anywhere.
   */
  private async resolvePolicyInstance(
    PolicyClass: Type<PolicyInstance>,
  ): Promise<PolicyInstance | undefined> {
    try {
      return this.moduleRef.get<PolicyInstance>(PolicyClass, { strict: false });
    } catch {
      // not a registered provider — instantiate via the container.
    }
    try {
      return await this.moduleRef.create<PolicyInstance>(PolicyClass);
    } catch {
      return undefined;
    }
  }
}

@Module({})
export class AuthzModule {
  static forRoot(options: AuthzModuleOptions = {}): DynamicModule {
    const policyProviders: Provider[] = (options.policies ?? []).map((P) => P as Provider);
    return {
      module: AuthzModule,
      global: true,
      imports: [DiscoveryModule],
      controllers: AuthzModule.canControllers(options.canEndpoint),
      providers: [
        { provide: AUTHZ_MODULE_OPTIONS, useValue: options },
        ...policyProviders,
        PolicyRegistry,
        Gate,
        CanGuard,
        { provide: APP_GUARD, useExisting: CanGuard },
        RolesGuard,
        { provide: APP_GUARD, useExisting: RolesGuard },
        ...AuthzModule.resourceResolverProviders(),
        ...AuthzModule.resourceHydratorProviders(),
        ...AuthzModule.bootstrapProviders(),
      ],
      exports: [
        Gate,
        PolicyRegistry,
        CanGuard,
        RolesGuard,
        AUTHZ_MODULE_OPTIONS,
        RESOURCE_RESOLVER,
        RESOURCE_HYDRATOR,
        ...(options.policies ?? []),
      ],
    };
  }

  static forRootAsync(options: AuthzModuleAsyncOptions): DynamicModule {
    const asyncProvider = AuthzModule.buildAsyncOptionsProvider(options);
    const asyncProviders = Array.isArray(asyncProvider) ? asyncProvider : [asyncProvider];
    return {
      module: AuthzModule,
      global: true,
      imports: [DiscoveryModule, ...((options.imports ?? []) as DynamicModule[])],
      controllers: AuthzModule.canControllers(options.canEndpoint),
      providers: [
        ...asyncProviders,
        PolicyRegistry,
        Gate,
        CanGuard,
        { provide: APP_GUARD, useExisting: CanGuard },
        RolesGuard,
        { provide: APP_GUARD, useExisting: RolesGuard },
        ...AuthzModule.resourceResolverProviders(),
        ...AuthzModule.resourceHydratorProviders(),
        ...AuthzModule.bootstrapProviders(),
      ],
      exports: [
        Gate,
        PolicyRegistry,
        CanGuard,
        RolesGuard,
        AUTHZ_MODULE_OPTIONS,
        RESOURCE_RESOLVER,
        RESOURCE_HYDRATOR,
      ],
    };
  }

  /**
   * Register a default {@link ResourceResolver} bound to {@link RESOURCE_RESOLVER}
   * so `@Can('update', Post)` works out-of-the-box on a clean install (no manual
   * resolver wiring needed). Reads the resolved options so a `resourceResolver`
   * override / `idParam` knob from forRoot OR forRootAsync is honored.
   */
  private static resourceResolverProviders(): Provider[] {
    return [
      {
        provide: RESOURCE_RESOLVER,
        useFactory: (options?: AuthzModuleOptions): ResourceResolver =>
          options?.resourceResolver ?? new IdParamResourceResolver(options?.idParam),
        inject: [{ token: AUTHZ_MODULE_OPTIONS, optional: true }],
      },
    ];
  }

  /**
   * Bind the {@link RESOURCE_HYDRATOR} token to the resolved options'
   * `resourceLoaders` map so the opt-in `POST /authz/can` endpoint can rehydrate a
   * `{ type, id }` shim into the REAL entity before authorizing. Reads the resolved
   * options so the map from forRoot OR a forRootAsync factory is honored. Resolves to
   * `undefined` when no `resourceLoaders` are configured (endpoint behavior unchanged).
   */
  private static resourceHydratorProviders(): Provider[] {
    return [
      {
        provide: RESOURCE_HYDRATOR,
        useFactory: (options?: AuthzModuleOptions): ResourceLoaderMap | undefined =>
          options?.resourceLoaders,
        inject: [{ token: AUTHZ_MODULE_OPTIONS, optional: true }],
      },
    ];
  }

  /**
   * Provider that populates the {@link PolicyRegistry} on init (explicit policies
   * + auto-discovered `@Policy` providers). Registered for both forRoot/forRootAsync.
   */
  private static bootstrapProviders(): Provider[] {
    return [AuthzPolicyBootstrap];
  }

  /**
   * Build the opt-in `POST /authz/can` fallback controller (or none). Off by
   * default; `true` mounts at the default path, a string mounts at that path.
   */
  private static canControllers(canEndpoint: boolean | string | undefined): Type<unknown>[] {
    if (!canEndpoint) return [];
    const path = typeof canEndpoint === 'string' ? canEndpoint : DEFAULT_CAN_ENDPOINT_PATH;
    return [createCanController(path)];
  }

  private static buildAsyncOptionsProvider(
    options: AuthzModuleAsyncOptions,
  ): Provider | Provider[] {
    if (options.useFactory) {
      return {
        provide: AUTHZ_MODULE_OPTIONS,
        useFactory: options.useFactory,
        inject: (options.inject ?? []) as Array<Type<unknown>>,
      };
    }
    if (options.useClass) {
      return [
        { provide: options.useClass, useClass: options.useClass },
        {
          provide: AUTHZ_MODULE_OPTIONS,
          useFactory: async (factory: AuthzModuleOptionsFactory) => factory.createAuthzOptions(),
          inject: [options.useClass],
        },
      ];
    }
    const factoryClass = options.useExisting as Type<AuthzModuleOptionsFactory>;
    return {
      provide: AUTHZ_MODULE_OPTIONS,
      useFactory: async (factory: AuthzModuleOptionsFactory) => factory.createAuthzOptions(),
      inject: [factoryClass],
    };
  }
}
