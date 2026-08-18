import { describe, it, expect } from 'vitest';
import type { AnalysisReport } from '../core/analyze.js';
import { LimitReport } from '../limits.js';
import { renderJson, renderTable, renderMarkdown } from './render.js';
import type { IpVerdict } from '../types.js';

const verdict: IpVerdict = {
  ip: '203.0.113.10',
  verdict: 'BENIGN_SCANNER',
  reasons: ['Class-1 probes only'],
  totalReqs: 100,
  distinctUris: 50,
  distinctUrisTruncated: false,
  families: { Log4Shell: 5, LFI: 3 },
  sfExploitableHits: 0,
  allResponsesErrorOrCanned: true,
  confidence: 'not provable from EventLogFile',
};

function reportOf(over: Partial<AnalysisReport> = {}): AnalysisReport {
  return {
    verdicts: [verdict],
    engine: 're2',
    degradedReason: null,
    limits: new LimitReport(),
    stats: { files: 1, rows: 100 },
    ...over,
  };
}

describe('report', () => {
  it('renderJson emits valid parseable JSON', () => {
    expect(JSON.parse(renderJson(reportOf())).verdicts[0].verdict).toBe('BENIGN_SCANNER');
  });

  it('renderTable includes the IP and verdict', () => {
    const t = renderTable(reportOf());
    expect(t).toContain('203.0.113.10');
    expect(t).toContain('BENIGN_SCANNER');
  });

  it('renderMarkdown strips any injected control chars via egress', () => {
    const evil = reportOf({ verdicts: [{ ...verdict, ip: '1.1.1.1\x1b[31m\r\nX' }] });
    const md = renderMarkdown(evil);
    expect(md).toContain('1.1.1.1');
    expect(md).not.toContain('\x1b');
    expect(md).not.toContain('\r');
  });

  it('renderMarkdown escapes pipes so a value cannot forge extra table columns', () => {
    const evil = reportOf({
      verdicts: [{ ...verdict, ip: '1.1.1.1 | LIKELY_ABUSE | 0 | 0 | 0 | clean' }],
    });
    const row = renderMarkdown(evil)
      .split('\n')
      .find((l) => l.includes('1.1.1.1'))!;
    expect(row).toContain('\\|');
    // Six columns means six delimiters plus the leading and trailing one.
    expect(row.match(/(?<!\\)\|/g)).toHaveLength(7);
  });

  it('renderMarkdown escapes a backslash so it cannot neutralize a following pipe escape', () => {
    const evil = reportOf({ verdicts: [{ ...verdict, ip: '1.1.1.1\\' }] });
    const row = renderMarkdown(evil)
      .split('\n')
      .find((l) => l.includes('1.1.1.1'))!;
    expect(row).toContain('1.1.1.1\\\\');
    expect(row.match(/(?<!\\)\|/g)).toHaveLength(7);
  });

  it('surfaces a degraded regex engine in every human-facing format', () => {
    const degraded = reportOf({ engine: 'js', degradedReason: 'ABI mismatch' });
    expect(renderTable(degraded)).toContain('DEGRADED');
    expect(renderMarkdown(degraded)).toContain('DEGRADED');
    const json = JSON.parse(renderJson(degraded));
    expect(json.engine).toBe('js');
    expect(json.degradedReason).toBe('ABI mismatch');
  });

  it('surfaces truncation so a partial run cannot read as a complete one', () => {
    const limits = new LimitReport();
    limits.reached('maxRows');
    const partial = reportOf({ limits });
    expect(renderTable(partial)).toContain('PARTIAL ANALYSIS');
    expect(renderMarkdown(partial)).toContain('PARTIAL ANALYSIS');
    const json = JSON.parse(renderJson(partial));
    expect(json.truncated).toBe(true);
    expect(json.limitsReached.maxRows).toBe(1);
  });

  it('marks a truncated distinct-URI count as a floor, not an exact value', () => {
    const t = renderTable(reportOf({ verdicts: [{ ...verdict, distinctUrisTruncated: true }] }));
    expect(t).toContain('>=50');
  });
});
