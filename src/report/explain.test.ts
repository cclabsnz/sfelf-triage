import { describe, it, expect } from 'vitest';
import { explainVerdict, explainJson } from './explain.js';

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

describe('explainJson', () => {
  it('describes all three verdicts, in severity order', () => {
    const out = JSON.parse(explainJson());
    expect(out.verdicts.map((v: { verdict: string }) => v.verdict)).toEqual([
      'BENIGN_SCANNER', 'SUSPICIOUS', 'LIKELY_ABUSE',
    ]);
    expect(out.verdicts[0].meaning).toMatch(/Class-1/);
  });

  it('carries the severity rank so a consumer can compare verdicts', () => {
    const out = JSON.parse(explainJson());
    expect(out.verdicts.map((v: { severity: number }) => v.severity)).toEqual([0, 1, 2]);
  });

  it('narrows to a single verdict', () => {
    const out = JSON.parse(explainJson('LIKELY_ABUSE'));
    expect(out.verdicts).toHaveLength(1);
    expect(out.verdicts[0].verdict).toBe('LIKELY_ABUSE');
  });

  it('reports an unknown verdict as an error object, not as an empty result', () => {
    const out = JSON.parse(explainJson('NOPE'));
    expect(out.error).toMatch(/unknown/i);
    expect(out.knownVerdicts).toEqual(['BENIGN_SCANNER', 'SUSPICIOUS', 'LIKELY_ABUSE']);
  });

  it('states the decision order and the scope limit machine-readably', () => {
    const out = JSON.parse(explainJson());
    expect(Array.isArray(out.decisionOrder)).toBe(true);
    expect(out.decisionOrder.length).toBeGreaterThan(0);
    expect(out.scope).toMatch(/EventLogFile/);
  });
});
