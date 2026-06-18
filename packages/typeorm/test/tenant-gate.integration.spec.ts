import 'reflect-metadata';
import { CONTEXT_ACCESSOR, Gate, PolicyRegistry } from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import type { DataSource } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { AuthzRbacModule } from '../src/authz-rbac.module.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
  targetDialect,
} from './support/datasource.js';

/**
 * A context accessor whose tenant can be flipped between checks. Each tenant flip
 * also swaps in a FRESH per-request store — mirroring production, where the request
 * (and thus the request-scoped permission cache) is new per request and the tenant
 * is constant within it.
 */
function mutableContext(): {
  accessor: { userRef: () => undefined; tenantId: () => string | undefined; get: () => object };
  setTenant: (t: string | undefined) => void;
} {
  let tenant: string | undefined;
  let store: object = {};
  return {
    accessor: {
      userRef: () => undefined,
      tenantId: () => tenant,
      get: () => store,
    },
    setTenant: (t) => {
      tenant = t;
      store = {}; // new request scope
    },
  };
}

describeIntegration(
  `Gate ↔ tenant-scoped RBAC (tenant from nestjs-context, ${targetDialect()})`,
  () => {
    let fx: AuthzFixture;
    let ds: DataSource;
    let store: TypeOrmAuthzStore;

    beforeEach(async () => {
      fx = await freshAuthzDataSource();
      ds = fx.ds;
      store = new TypeOrmAuthzStore(ds, fx.options);
      await store.ensureSchema();
      await store.givePermissionToRole('editor', 'posts.publish');
    });

    afterEach(async () => {
      await ds.destroy();
    });

    it('a tenant-scoped role only grants within that tenant (Gate reads tenant from context)', async () => {
      await store.assignRole({ type: 'user', id: 42 }, 'editor', { tenantId: 'acme' });
      const ctx = mutableContext();

      const moduleRef = await Test.createTestingModule({
        imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
        providers: [PolicyRegistry, Gate, { provide: CONTEXT_ACCESSOR, useValue: ctx.accessor }],
      }).compile();
      await moduleRef.init();
      const gate = moduleRef.get(Gate);
      const user = gate.forUser({ type: 'user', id: 42 });

      ctx.setTenant('acme');
      expect(await user.allows('posts.publish')).toBe(true);

      ctx.setTenant('globex');
      await expect(user.allows('posts.publish')).rejects.toThrow();

      await moduleRef.close();
    });

    it('a DIRECT user permission grants without any role, regardless of tenant', async () => {
      await store.giveUserPermission({ type: 'user', id: 7 }, 'reports.export');
      const ctx = mutableContext();

      const moduleRef = await Test.createTestingModule({
        imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
        providers: [PolicyRegistry, Gate, { provide: CONTEXT_ACCESSOR, useValue: ctx.accessor }],
      }).compile();
      await moduleRef.init();
      const gate = moduleRef.get(Gate);
      const user = gate.forUser({ type: 'user', id: 7 });

      ctx.setTenant('acme');
      expect(await user.allows('reports.export')).toBe(true);
      ctx.setTenant(undefined);
      expect(await user.allows('reports.export')).toBe(true);

      await moduleRef.close();
    });

    it('Gate.hasRole is tenant-scoped via the role provider', async () => {
      await store.assignRole({ type: 'user', id: 9 }, 'editor', { tenantId: 'acme' });
      const ctx = mutableContext();

      const moduleRef = await Test.createTestingModule({
        imports: [AuthzRbacModule.forRoot({ store, autoCreateSchema: false })],
        providers: [PolicyRegistry, Gate, { provide: CONTEXT_ACCESSOR, useValue: ctx.accessor }],
      }).compile();
      await moduleRef.init();
      const gate = moduleRef.get(Gate);
      const user = gate.forUser({ type: 'user', id: 9 });

      ctx.setTenant('acme');
      expect(await user.hasRole('editor')).toBe(true);
      ctx.setTenant('globex');
      expect(await user.hasRole('editor')).toBe(false);

      await moduleRef.close();
    });
  },
);
