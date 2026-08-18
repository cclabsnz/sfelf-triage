import { describe, it, expect } from 'vitest';
import { DEFAULT_LIMITS, LimitReport } from './limits.js';

describe('LimitReport', () => {
  it('reports a run that hit nothing as complete, with no summary to show', () => {
    const r = new LimitReport();
    expect(r.truncated).toBe(false);
    expect(r.summary()).toBeNull();
    expect(r.toJSON()).toEqual({});
  });

  it('counts how many times each ceiling bit', () => {
    const r = new LimitReport();
    r.reached('maxRows');
    r.reached('maxUrisPerIp');
    r.reached('maxUrisPerIp');
    expect(r.truncated).toBe(true);
    expect(r.toJSON()).toEqual({ maxRows: 1, maxUrisPerIp: 2 });
  });

  it('names the ceiling and its configured value, so the fix is obvious', () => {
    const r = new LimitReport();
    r.reached('maxRows');
    const summary = r.summary()!;
    expect(summary).toContain('PARTIAL ANALYSIS');
    expect(summary).toContain(`maxRows=${DEFAULT_LIMITS.maxRows}`);
    expect(summary).toMatch(/lower bound/i);
  });

  it('serializes deterministically regardless of the order ceilings were hit', () => {
    const a = new LimitReport();
    a.reached('maxRows');
    a.reached('maxFiles');
    const b = new LimitReport();
    b.reached('maxFiles');
    b.reached('maxRows');
    expect(Object.keys(a.toJSON())).toEqual(Object.keys(b.toJSON()));
  });
});

describe('DEFAULT_LIMITS', () => {
  it('bounds every accumulator with a positive, finite ceiling', () => {
    for (const [name, value] of Object.entries(DEFAULT_LIMITS)) {
      expect(Number.isFinite(value), name).toBe(true);
      expect(value, name).toBeGreaterThan(0);
    }
  });
});

describe('LimitReport: effective limits', () => {
  // The summary previously read DEFAULT_LIMITS at render time, so a run bounded by
  // --max-rows 2 reported "maxRows=5000000" — naming a ceiling the run never used.
  it('quotes the ceiling the run actually used, not the default', () => {
    const r = new LimitReport({ ...DEFAULT_LIMITS, maxRows: 2 });
    r.reached('maxRows');
    expect(r.summary()).toContain('maxRows=2');
    expect(r.summary()).not.toContain(`maxRows=${DEFAULT_LIMITS.maxRows}`);
  });
});
