import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import { PolicyFor, policyForResource } from '../src/links.js';

describe('@PolicyFor', () => {
  it('throws when a resource is already linked to another policy', () => {
    class Invoice {}
    @PolicyFor(Invoice)
    class InvoicePolicy {}

    expect(() => {
      @PolicyFor(Invoice)
      class OtherInvoicePolicy {}
      return OtherInvoicePolicy;
    }).toThrow(/Invoice is already linked to InvoicePolicy/);
    expect(policyForResource(Invoice)).toBe(InvoicePolicy);
  });

  it('linking the same pair again is a no-op', () => {
    class Receipt {}
    class ReceiptPolicy {}
    PolicyFor(Receipt)(ReceiptPolicy);
    expect(() => PolicyFor(Receipt)(ReceiptPolicy)).not.toThrow();
    expect(policyForResource(Receipt)).toBe(ReceiptPolicy);
  });

  it('a re-declared policy class of the same name replaces the link', () => {
    class Note {}
    const declare = () => {
      @PolicyFor(Note)
      class NotePolicy {}
      return NotePolicy;
    };
    declare();
    const second = declare();
    expect(policyForResource(Note)).toBe(second);
  });
});
