import { describe, it, expect } from 'vitest';
import { score } from './score.js';
import { ingress } from '../sanitizer/ingress.js';
import { Matcher } from './match.js';

const m = new Matcher();
const me = (row: Record<string, string>, type: string) => m.match(ingress(row, type));

describe('score', () => {
  it('returns BENIGN_SCANNER when probes are Class-1-only and responses are error/canned', () => {
    const events = [
      me({ URI: '/app/etc/passwd', CLIENT_IP: '13.210.1.103', IS_ERROR: '1', RESPONSE_SIZE: '0' }, 'Sites'),
      me({ URI: '/sfsites/${jndi:ldap://x.nessus.org}', CLIENT_IP: '13.210.1.103', IS_ERROR: '0', RESPONSE_SIZE: '419991' }, 'Sites'),
      me({ URI: '/sfsites/reports/rwservlet', CLIENT_IP: '13.210.1.103', IS_ERROR: '0', RESPONSE_SIZE: '419991' }, 'Sites'),
      me({ URI: '/login/reports/rwservlet', CLIENT_IP: '13.210.1.103', IS_ERROR: '0', RESPONSE_SIZE: '419991' }, 'Sites'),
    ];
    const [v] = score(events, []);
    expect(v.ip).toBe('13.210.1.103');
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
});
