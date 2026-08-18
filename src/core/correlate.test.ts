import { describe, it, expect } from 'vitest';
import { correlate, Correlator, DEFAULT_WINDOW_MS } from './correlate.js';
import { DEFAULT_LIMITS, LimitReport } from '../limits.js';
import { ingress } from '../sanitizer/ingress.js';

describe('correlate', () => {
  it('flags a file read followed by a download from the same IP within the window', () => {
    const read = ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'uiapi { query { ContentVersion { edges } } }',
      TIMESTAMP_DERIVED: '2024-02-20T00:00:00.000Z' }, 'GraphQlQueryExecution');
    const dl = ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T00:01:00.000Z' }, 'ContentTransfer');
    const res = correlate([read, dl]);
    expect(res).toHaveLength(1);
    expect(res[0].kind).toBe('read-then-download');
  });

  it('does not flag when the download is outside the window', () => {
    const read = ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'uiapi { query { ContentVersion { edges } } }',
      TIMESTAMP_DERIVED: '2024-02-20T00:00:00.000Z' }, 'GraphQlQueryExecution');
    const dl = ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T01:00:00.000Z' }, 'ContentTransfer');
    expect(correlate([read, dl])).toHaveLength(0);
  });

  it('does not pair a read with a download from a different IP', () => {
    const read = ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'ContentVersion',
      TIMESTAMP_DERIVED: '2024-02-20T00:00:00.000Z' }, 'GraphQlQueryExecution');
    const dl = ingress({ CLIENT_IP: '8.8.8.8', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T00:01:00.000Z' }, 'ContentTransfer');
    expect(correlate([read, dl])).toHaveLength(0);
  });

  it('does not pair a download with a read that happened after it', () => {
    const dl = ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T00:00:00.000Z' }, 'ContentTransfer');
    const read = ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'ContentVersion',
      TIMESTAMP_DERIVED: '2024-02-20T00:01:00.000Z' }, 'GraphQlQueryExecution');
    expect(correlate([dl, read])).toHaveLength(0);
  });

  it('pairs correctly when reads arrive out of chronological order', () => {
    const at = (iso: string) => ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'ContentVersion',
      TIMESTAMP_DERIVED: iso }, 'GraphQlQueryExecution');
    const dl = ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
      TIMESTAMP_DERIVED: '2024-02-20T05:00:30.000Z' }, 'ContentTransfer');
    // Only the 05:00:00 read is inside the window; it is added last.
    const res = correlate([at('2024-02-20T01:00:00.000Z'), dl, at('2024-02-20T05:00:00.000Z')]);
    expect(res).toHaveLength(1);
    expect(res[0].readTs).toBe(Date.parse('2024-02-20T05:00:00.000Z'));
  });
});

// A host issuing many file reads and downloads is exactly the behaviour this rule
// detects, so the matching cost must not grow with how hard that host works.
describe('Correlator: bounded state', () => {
  const read = (ms: number) => ingress({ CLIENT_IP: '9.9.9.9', QUERY: 'ContentVersion',
    TIMESTAMP_DERIVED: new Date(ms).toISOString() }, 'GraphQlQueryExecution');
  const download = (ms: number) => ingress({ CLIENT_IP: '9.9.9.9', URI: '/sfc/servlet.shepherd',
    TIMESTAMP_DERIVED: new Date(ms).toISOString() }, 'ContentTransfer');

  it('retains only correlation candidates, not the event stream', () => {
    const report = new LimitReport();
    const c = new Correlator(DEFAULT_WINDOW_MS, DEFAULT_LIMITS, report);
    const base = Date.parse('2024-02-20T00:00:00.000Z');
    for (let i = 0; i < 20_000; i++) {
      // Unrelated traffic: neither a file read nor a download, so nothing is kept.
      c.add(ingress({ CLIENT_IP: '9.9.9.9', URI: `/login/?n=${i}`,
        TIMESTAMP_DERIVED: new Date(base + i).toISOString() }, 'Sites'));
    }
    c.add(read(base));
    c.add(download(base + 1_000));
    expect(c.finish()).toHaveLength(1);
    expect(report.truncated).toBe(false);
  });

  it('handles many reads and downloads for one IP quickly', () => {
    const c = new Correlator();
    const base = Date.parse('2024-02-20T00:00:00.000Z');
    // Reads every hour, downloads every hour a minute later: each download has exactly
    // one in-window read, so a correct matcher returns one correlation per download.
    for (let i = 0; i < 5_000; i++) c.add(read(base + i * 3_600_000));
    for (let i = 0; i < 5_000; i++) c.add(download(base + i * 3_600_000 + 60_000));
    const start = Date.now();
    const res = c.finish();
    expect(res).toHaveLength(5_000);
    expect(Date.now() - start).toBeLessThan(2_000);
  });

  it('caps retained candidates per IP and records the truncation', () => {
    const report = new LimitReport();
    const c = new Correlator(DEFAULT_WINDOW_MS, { ...DEFAULT_LIMITS, maxCorrelationEventsPerIp: 5 }, report);
    const base = Date.parse('2024-02-20T00:00:00.000Z');
    for (let i = 0; i < 50; i++) c.add(read(base + i));
    c.add(download(base + 1_000));
    expect(c.finish()).toHaveLength(1);
    expect(report.toJSON().maxCorrelationEventsPerIp).toBeGreaterThan(0);
  });
});
