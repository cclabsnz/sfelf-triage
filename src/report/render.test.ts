import { describe, it, expect } from 'vitest';
import { renderJson, renderTable, renderMarkdown } from './render.js';
import type { IpVerdict } from '../types.js';

const v: IpVerdict[] = [{
  ip: '203.0.113.10', verdict: 'BENIGN_SCANNER',
  reasons: ['Class-1 probes only'], totalReqs: 100, distinctUris: 50,
  families: { Log4Shell: 5, 'LFI': 3 }, sfExploitableHits: 0,
  allResponsesErrorOrCanned: true,
  confidence: 'not provable from EventLogFile',
}];

describe('report', () => {
  it('renderJson emits valid parseable JSON', () => {
    expect(JSON.parse(renderJson(v))[0].verdict).toBe('BENIGN_SCANNER');
  });

  it('renderTable includes the IP and verdict', () => {
    const t = renderTable(v);
    expect(t).toContain('203.0.113.10');
    expect(t).toContain('BENIGN_SCANNER');
  });

  it('renderMarkdown strips any injected control chars via egress', () => {
    const evil: IpVerdict[] = [{ ...v[0], ip: '1.1.1.1\x1b[31m\r\nX' }];
    const md = renderMarkdown(evil);
    expect(md).toContain('1.1.1.1');
    expect(md).not.toContain('\x1b');
    expect(md).not.toContain('\r');
  });
});
