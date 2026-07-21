import { describe, it, expect } from 'vitest';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from './analyze.js';

const here = dirname(fileURLToPath(import.meta.url));

describe('analyze (golden fixtures)', () => {
  it('classifies the benign-scan golden fixture as BENIGN_SCANNER', async () => {
    const verdicts = await analyze(join(here, '__fixtures__/benign'));
    const v = verdicts.find(x => x.ip === '203.0.113.10')!;
    expect(v.verdict).toBe('BENIGN_SCANNER');
    expect(v.sfExploitableHits).toBe(0);
    expect(Object.keys(v.families)).toEqual(expect.arrayContaining(['Log4Shell', 'LFI', 'Oracle-Reports']));
  });

  it('classifies the exfil-cluster golden fixture as LIKELY_ABUSE', async () => {
    const verdicts = await analyze(join(here, '__fixtures__/abuse'));
    const v = verdicts.find(x => x.ip === '198.51.100.23')!;
    expect(v.verdict).toBe('LIKELY_ABUSE');
    expect(v.sfExploitableHits).toBeGreaterThan(0);
  });
});
