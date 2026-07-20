import { describe, it, expect } from 'vitest';
import { loadCatalog } from './catalog/index.js';
import { SafeMatcher } from './matcher/safeMatcher.js';
import { ingress } from './sanitizer/ingress.js';
import { egress } from './sanitizer/egress.js';

describe('security: the analyzer survives its own catalog', () => {
  const rules = loadCatalog();
  const matcher = new SafeMatcher();

  const payloads = [
    '/sfsites/${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://x.nessus.org}',
    '/app/etc/passwd',
    '/sfsites/ HTTP/1.1\r\nWas-Header: \x1b[31mX',
    '=cmd|calc',
    '(a+)+$' + 'a'.repeat(4000),
  ];

  it('runs every rule over every payload without hanging', () => {
    const start = Date.now();
    for (const p of payloads) {
      const ev = ingress({ URI: p, CLIENT_IP: '1.1.1.1' }, 'Sites');
      for (const r of rules) matcher.test(r.pattern, ev.uri);
    }
    expect(Date.now() - start).toBeLessThan(2000);
  });

  it('egress leaves no ANSI or control chars in rendered payloads', () => {
    for (const p of payloads) {
      const out = egress(ingress({ URI: p, CLIENT_IP: '1.1.1.1' }, 'Sites').uri);
      expect(out).not.toMatch(/[\x00-\x1f\x7f]/);
    }
  });
});
