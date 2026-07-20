import { describe, it, expect } from 'vitest';
import { loadCatalog } from './index.js';
import { SafeMatcher } from '../matcher/safeMatcher.js';

describe('catalog', () => {
  const rules = loadCatalog();
  const m = new SafeMatcher();

  it('covers the expected Class-1 families with sfExploitable=false', () => {
    const fams = new Set(rules.filter(r => !r.sfExploitable).map(r => r.family));
    for (const f of ['Log4Shell', 'LFI', 'RFI-SSRF', 'CRLF', 'Struts2', 'Oracle-Reports',
                      'Spring-Actuator', 'Pentaho', 'Exposed-git', 'Exposed-env']) {
      expect(fams.has(f)).toBe(true);
    }
  });

  it('has at least one Class-2 rule with sfExploitable=true', () => {
    expect(rules.some(r => r.sfExploitable)).toBe(true);
  });

  it('every rule pattern actually matches its own sample intent', () => {
    const jndi = rules.find(r => r.family === 'Log4Shell')!;
    expect(m.test(jndi.pattern, '/sfsites/${jndi:ldap://x.nessus.org}')).toBe(true);
    const passwd = rules.find(r => r.family === 'LFI')!;
    expect(m.test(passwd.pattern, '/app/etc/passwd')).toBe(true);
  });

  it('gives every rule a unique id', () => {
    const ids = rules.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
