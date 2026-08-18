import { describe, it, expect } from 'vitest';
import { ingress, normalizeIp, MAX_FIELD, MAX_IP_FIELD, UNKNOWN_IP } from './ingress.js';
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

// Every per-IP counter and threshold is keyed on this string, so any address the same
// host can write two ways is a way to split its own activity across two report rows.
describe('Sanitizer.normalizeIp', () => {
  it('collapses an IPv4-mapped IPv6 address onto its IPv4 identity', () => {
    expect(normalizeIp('::ffff:203.0.113.9')).toBe('203.0.113.9');
    expect(normalizeIp('::ffff:203.0.113.9')).toBe(normalizeIp('203.0.113.9'));
  });

  it('collapses equivalent IPv6 spellings onto one identity', () => {
    const compressed = normalizeIp('2001:db8::1');
    expect(normalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(compressed);
    expect(normalizeIp('2001:DB8::1')).toBe(compressed);
  });

  it('leaves a plain IPv4 address unchanged', () => {
    expect(normalizeIp('198.51.100.23')).toBe('198.51.100.23');
  });

  it('maps a missing or blank address to a single explicit identity', () => {
    expect(normalizeIp(undefined)).toBe(UNKNOWN_IP);
    expect(normalizeIp('')).toBe(UNKNOWN_IP);
    expect(normalizeIp('   ')).toBe(UNKNOWN_IP);
  });

  it('preserves a non-address marker verbatim rather than dropping the row', () => {
    expect(normalizeIp('Salesforce Internal')).toBe('Salesforce Internal');
  });

  // ipaddr.js resolves legacy IPv4 notations — 0203.0.113.9 is octal for 131.0.113.9,
  // 2130706433 is 127.0.0.1. Resolving them would print an address that appears nowhere
  // in the log: a false attribution against a host that was never seen.
  it.each([
    ['0203.0.113.9', 'octal'],
    ['0x7f.0.0.1', 'hex'],
    ['2130706433', 'integer'],
    ['203.000.113.009', 'zero-padded'],
    ['1.2.3.4.5', 'malformed'],
  ])('keeps the %s form exactly as the log wrote it (%s)', (input) => {
    expect(normalizeIp(input)).toBe(input);
  });

  it('does not collapse a mapped address whose embedded IPv4 part is ambiguous', () => {
    expect(normalizeIp('::ffff:0203.0.113.9')).not.toBe('203.0.113.9');
  });

  it('caps an oversized value so the identity key cannot carry a payload', () => {
    expect(normalizeIp('a'.repeat(5000))).toHaveLength(MAX_IP_FIELD);
  });
});
