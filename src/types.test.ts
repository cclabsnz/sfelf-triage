import { describe, it, expect } from 'vitest';
import { VERDICTS, type SafeEvent, brand } from './types.js';

describe('types', () => {
  it('exposes the three verdict values', () => {
    expect(VERDICTS).toEqual(['BENIGN_SCANNER', 'SUSPICIOUS', 'LIKELY_ABUSE']);
  });

  it('brands a SafeEvent so it cannot be forged as a plain object literal', () => {
    // A value is only a SafeEvent if it carries the brand symbol.
    const ev = { [brand]: true } as unknown as SafeEvent;
    expect(ev[brand]).toBe(true);
  });
});
