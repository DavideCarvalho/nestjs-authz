import 'reflect-metadata';
import { Policy } from '@nestjs/authorization';
import { Module } from '@nestjs/common';
import { LazyModuleLoader } from '@nestjs/core';
import { describe, expect, it } from 'vitest';
import { PolicyFor } from '../src/links.js';
import { PolicyIndex } from '../src/policy-index.js';
import { bootContext } from './support/app.js';

class Article {}
class Invoice {}

@PolicyFor(Article)
class ArticlePolicy {
  create(_user: unknown) {
    return true;
  }
}

@Policy()
@PolicyFor(Invoice)
class InvoicePolicy {
  create(_user: unknown) {
    return true;
  }
}

@Module({ providers: [InvoicePolicy] })
class InvoicesModule {}

describe('PolicyIndex', () => {
  it('sees policies of a lazily loaded module after a first lookup', async () => {
    const { mod } = await bootContext({ providers: [ArticlePolicy] });
    const index = mod.get(PolicyIndex);
    const names = () => index.resourcePolicies().map((p) => p.policy.name);

    expect(names()).toEqual(['ArticlePolicy']);
    expect(index.classAbilities().map((p) => p.policy.name)).toEqual(['ArticlePolicy']);

    await mod.get(LazyModuleLoader).load(() => InvoicesModule);

    expect(names()).toEqual(['ArticlePolicy', 'InvoicePolicy']);
    expect(index.classAbilities().map((p) => p.policy.name)).toEqual([
      'ArticlePolicy',
      'InvoicePolicy',
    ]);
    expect(index.instanceOf(InvoicePolicy)).toBeInstanceOf(InvoicePolicy);
  });

  it('reuses the scan while the container is unchanged', async () => {
    const { mod } = await bootContext({ providers: [ArticlePolicy] });
    const index = mod.get(PolicyIndex);
    expect(index.all()).toBe(index.all());
  });
});
