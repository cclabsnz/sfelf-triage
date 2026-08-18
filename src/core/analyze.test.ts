import { describe, it, expect } from 'vitest';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_LIMITS } from '../limits.js';
import { analyze } from './analyze.js';

const here = dirname(fileURLToPath(import.meta.url));

describe('analyze (golden fixtures)', () => {
  it('classifies the benign-scan golden fixture as BENIGN_SCANNER', async () => {
    const report = await analyze(join(here, '__fixtures__/benign'));
    const v = report.verdicts.find((x) => x.ip === '203.0.113.10')!;
    expect(v.verdict).toBe('BENIGN_SCANNER');
    expect(v.sfExploitableHits).toBe(0);
    expect(Object.keys(v.families)).toEqual(
      expect.arrayContaining(['Log4Shell', 'LFI', 'Oracle-Reports']),
    );
  });

  it('classifies the exfil-cluster golden fixture as LIKELY_ABUSE', async () => {
    const report = await analyze(join(here, '__fixtures__/abuse'));
    const v = report.verdicts.find((x) => x.ip === '198.51.100.23')!;
    expect(v.verdict).toBe('LIKELY_ABUSE');
    expect(v.sfExploitableHits).toBeGreaterThan(0);
  });

  it('reports a complete run as untruncated, with the engine that produced it', async () => {
    const report = await analyze(join(here, '__fixtures__/benign'));
    expect(report.limits.truncated).toBe(false);
    expect(['re2', 'js']).toContain(report.engine);
    expect(report.stats.rows).toBeGreaterThan(0);
    expect(report.stats.files).toBeGreaterThan(0);
  });

  it('stops at the row ceiling and reports the run as partial', async () => {
    const report = await analyze(join(here, '__fixtures__/benign'), {
      limits: { ...DEFAULT_LIMITS, maxRows: 2 },
    });
    expect(report.stats.rows).toBe(2);
    expect(report.limits.truncated).toBe(true);
    expect(report.limits.toJSON().maxRows).toBeGreaterThan(0);
    expect(report.limits.summary()).toContain('PARTIAL ANALYSIS');
  });
});
