import { describe, it, expect } from 'vitest';
import { explainVerdict } from './explain.js';

describe('explainVerdict', () => {
  it('explains a single verdict with its decision context', () => {
    const out = explainVerdict('LIKELY_ABUSE');
    expect(out).toContain('LIKELY_ABUSE');
    expect(out).toContain('read-then-download');
    expect(out).toMatch(/bounds, not proves/i);
  });

  it('explains all three verdicts when no argument is given', () => {
    const out = explainVerdict();
    expect(out).toContain('BENIGN_SCANNER');
    expect(out).toContain('SUSPICIOUS');
    expect(out).toContain('LIKELY_ABUSE');
  });

  it('reports an unknown verdict', () => {
    expect(explainVerdict('NONSENSE')).toMatch(/Unknown verdict/);
  });

  it('emits no ANSI or control chars', () => {
    expect(explainVerdict()).not.toMatch(/[\x00-\x08\x0e-\x1f\x7f]/);
  });
});
