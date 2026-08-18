import { describe, it, expect } from 'vitest';
import { SafeMatcher, loadRe2, describeLoadFailure } from './safeMatcher.js';

describe('SafeMatcher', () => {
  const m = new SafeMatcher();

  it('matches a case-insensitive substring pattern', () => {
    expect(m.test('jndi', 'x${JNDI:ldap}')).toBe(true);
    expect(m.test('jndi', '/login/')).toBe(false);
  });

  // Linear-time matching on a hostile *pattern* is RE2's guarantee and RE2's alone. The
  // JS fallback is not merely slower here: `(a+)+$` against 5000 characters does not
  // finish in any practical time, so feeding it to the fallback hangs the suite rather
  // than failing it. That is precisely what happened in CI once re2 stopped building.
  it.runIf(m.engine === 're2')(
    'runs a catastrophic-backtracking pattern in linear time under RE2',
    () => {
      const start = Date.now();
      // codeql[js/redos] — this pattern is the fixture, not shipped code. Its exponential
      // backtracking is the property under test: RE2 must run it in linear time. It is
      // never matched on the JS engine (see the runIf guard above), and no catalog rule
      // is permitted to look like it — security.test.ts enforces that against every rule.
      const res = m.test('(a+)+$', 'a'.repeat(5000) + 'b');
      expect(Date.now() - start).toBeLessThan(1000);
      expect(typeof res).toBe('boolean');
    },
  );

  // What actually protects the fallback is that patterns come only from our catalog.
  // That invariant is enforced in security.test.ts, against the JS engine specifically.
  it('bounds input length before matching, whichever engine is active', () => {
    const start = Date.now();
    expect(typeof m.test('log4j2?[.-][a-z]', 'a'.repeat(50_000))).toBe('boolean');
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('reports which engine is active', () => {
    expect(['re2', 'js']).toContain(m.engine);
  });

  it('reports no degradation reason when RE2 loaded', () => {
    if (m.engine === 're2') expect(m.degradedReason).toBeNull();
    else expect(m.degradedReason).toBeTruthy();
  });

  // The fallback is the tool's single largest silent-failure risk: an install that
  // looks healthy still matches with a backtracking engine. These pin the diagnostics
  // rather than the binding, so they hold on any host.
  describe('when the native binding cannot load', () => {
    it('falls back to the JS engine and states why', () => {
      const fallback = new SafeMatcher(() => ({ ctor: null, reason: 'binding missing' }));
      expect(fallback.engine).toBe('js');
      expect(fallback.degradedReason).toBe('binding missing');
      expect(fallback.test('jndi', 'x${JNDI:ldap}')).toBe(true);
    });

    it('never leaves degradedReason unset, even for an unexplained failure', () => {
      const fallback = new SafeMatcher(() => ({ ctor: null, reason: null }));
      expect(fallback.engine).toBe('js');
      expect(fallback.degradedReason).toMatch(/unknown reason/i);
    });

  });

  // The ABI mismatch is the failure that actually happens in the field: a Node upgrade
  // leaves a working-looking install whose native binding no longer loads. The message
  // has to name the fix, because the default reaction to "re2 unavailable" is to
  // reinstall, which does not rebuild.
  describe('describeLoadFailure', () => {
    it('explains an ABI mismatch as a rebuild, naming the running Node version', () => {
      const reason = describeLoadFailure(
        Object.assign(
          new Error(
            "The module '/x/re2.node'\nwas compiled against a different Node.js version using\n" +
              'NODE_MODULE_VERSION 127. This version of Node.js requires\nNODE_MODULE_VERSION 147.',
          ),
          { code: 'ERR_DLOPEN_FAILED' },
        ),
      );
      expect(reason).toMatch(/rebuild it with "pnpm rebuild re2"/);
      expect(reason).toContain(process.version);
    });

    it('explains a missing package as an install', () => {
      const reason = describeLoadFailure(
        Object.assign(new Error("Cannot find module 're2'"), { code: 'MODULE_NOT_FOUND' }),
      );
      expect(reason).toMatch(/pnpm install/);
    });

    it('falls back to the error text for anything unrecognized', () => {
      expect(describeLoadFailure(new Error('something else entirely'))).toContain(
        'something else entirely',
      );
    });
  });

  it('loadRe2 returns a usable constructor or a stated reason, never both empty', () => {
    const { ctor, reason } = loadRe2();
    expect(ctor === null ? reason : 'loaded').toBeTruthy();
  });
});
