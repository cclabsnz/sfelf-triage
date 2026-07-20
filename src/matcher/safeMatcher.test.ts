import { describe, it, expect } from 'vitest';
import { SafeMatcher } from './safeMatcher.js';

describe('SafeMatcher', () => {
  const m = new SafeMatcher();

  it('matches a case-insensitive substring pattern', () => {
    expect(m.test('jndi', 'x${JNDI:ldap}')).toBe(true);
    expect(m.test('jndi', '/login/')).toBe(false);
  });

  it('does not hang on a catastrophic-backtracking pattern within the length cap', () => {
    const evil = '(a+)+$';
    const input = 'a'.repeat(5000) + 'b'; // never longer than MAX_FIELD
    const start = Date.now();
    const res = m.test(evil, input);
    expect(Date.now() - start).toBeLessThan(1000); // completes fast: re2 is linear; js path is length-bounded
    expect(typeof res).toBe('boolean');
  });

  it('reports which engine is active', () => {
    expect(['re2', 'js']).toContain(m.engine);
  });
});
