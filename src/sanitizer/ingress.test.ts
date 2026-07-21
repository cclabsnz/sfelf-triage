import { describe, it, expect } from 'vitest';
import { ingress, MAX_FIELD } from './ingress.js';
import { brand } from '../types.js';

describe('Sanitizer.ingress', () => {
  it('URL-decodes the URI (multi-pass) and brands the result', () => {
    const row = { URI: '%2524%257Bjndi%253Aldap%253A%252Fx%257D', CLIENT_IP: '1.2.3.4' };
    const ev = ingress(row, 'Sites');
    expect(ev[brand]).toBe(true);
    expect(ev.uri).toBe('${jndi:ldap:/x}');
    expect(ev.clientIp).toBe('1.2.3.4');
  });

  it('caps every field at MAX_FIELD bytes to bound downstream regex input', () => {
    const long = 'a'.repeat(MAX_FIELD + 5000);
    const ev = ingress({ URI: long, CLIENT_IP: '1.2.3.4' }, 'URI');
    expect(ev.uri.length).toBe(MAX_FIELD);
  });

  it('parses response signals and derived timestamp', () => {
    const ev = ingress(
      { URI: '/x', CLIENT_IP: '1.2.3.4', IS_ERROR: '0', RESPONSE_SIZE: '420',
        TIMESTAMP_DERIVED: '2024-01-15T04:02:34.467Z' },
      'Sites',
    );
    expect(ev.isError).toBe(false);
    expect(ev.responseSize).toBe(420);
    expect(ev.ts).toBe(Date.parse('2024-01-15T04:02:34.467Z'));
  });

  it('never throws on malformed encoding — returns the raw field', () => {
    const ev = ingress({ URI: '%', CLIENT_IP: '1.2.3.4' }, 'URI');
    expect(ev.uri).toBe('%');
  });
});
