import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { loadCatalog } from './catalog/index.js';
import { SafeMatcher } from './matcher/safeMatcher.js';
import { ingress, MAX_FIELD } from './sanitizer/ingress.js';
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

/**
 * The JS fallback is NOT ReDoS-proof in general, and the field cap does not make it so:
 * a nested quantifier like `(a+)+$` blows up at roughly 30 characters, four orders of
 * magnitude below MAX_FIELD. The property that actually keeps the fallback safe is
 * narrower — every pattern the matcher ever runs comes from this catalog, and no catalog
 * pattern backtracks catastrophically.
 *
 * That is an invariant of the catalog rather than of the matcher, so it is tested against
 * the catalog, on the engine that is actually vulnerable. A new rule with a nested
 * quantifier fails here instead of hanging a triage run on a host without RE2.
 */
describe('security: catalog patterns are safe on the backtracking engine', () => {
  const rules = loadCatalog();

  it('the forced-fallback matcher really is the backtracking engine', () => {
    const js = new SafeMatcher(() => ({ ctor: null, reason: 'forced JS engine for this test' }));
    expect(js.engine).toBe('js');
  });

  // Each pattern runs in a child process with a hard kill.
  //
  // Running it in-process would defeat the purpose: a catastrophic regex blocks the event
  // loop synchronously, so no test timeout can interrupt it and an assertion on elapsed
  // time is never reached. The suite would hang exactly the way CI hung, instead of naming
  // the offending rule. Only a separate process can be killed.
  //
  // The spawn is async rather than `spawnSync` because these tests run inside a worker
  // thread and the sync form would block it for the duration of every probe.
  it.each(rules.map((r) => [r.id, r.pattern] as const))(
    'rule %s stays fast on adversarial input',
    async (id, pattern) => {
      const outcome = await runProbe(pattern);
      if (outcome !== 'ok') {
        throw new Error(
          `catalog rule "${id}" is not safe on the JS fallback engine.\nPattern: ${pattern}\n${outcome}`,
        );
      }
    },
    PROBE_TIMEOUT_MS * 3,
  );
});

const execFileAsync = promisify(execFile);
const PROBE_TIMEOUT_MS = 5_000;

/**
 * Runs one pattern in a killable child; resolves 'ok' or a description of the failure.
 *
 * Uses execFile's built-in `timeout` and `killSignal` rather than a hand-rolled
 * `setTimeout` + `kill`, so the timer and the child handle are owned and cleaned up by
 * Node instead of by this file.
 */
async function runProbe(pattern: string): Promise<string> {
  try {
    await execFileAsync(process.execPath, ['-e', PROBE], {
      env: { ...process.env, SFELF_PATTERN: pattern, SFELF_MAX_FIELD: String(MAX_FIELD) },
      timeout: PROBE_TIMEOUT_MS,
      killSignal: 'SIGKILL',
    });
    return 'ok';
  } catch (err) {
    const e = err as { killed?: boolean; code?: number | string; stderr?: string };
    if (e.killed) {
      return (
        `It did not finish within ${PROBE_TIMEOUT_MS}ms and was killed — catastrophic ` +
        'backtracking. Rewrite it without nested or overlapping quantifiers.'
      );
    }
    return `The probe exited ${e.code}: ${(e.stderr ?? '').trim()}`;
  }
}

/**
 * Runs one catalog pattern against adversarial inputs on the plain JS engine. Inputs are
 * shaped to maximize backtracking: long single-character runs, long runs that nearly
 * match and fail at the very end, and repeated near-miss structure.
 */
const PROBE = `
  const pattern = process.env.SFELF_PATTERN;
  const MAX = Number(process.env.SFELF_MAX_FIELD);
  const inputs = [
    'a'.repeat(MAX),
    'a'.repeat(MAX - 1) + 'b',
    '/'.repeat(MAX),
    '\${'.repeat(MAX / 2),
    ('log4j' + '.'.repeat(50)).repeat(100),
    ('/.git/' + 'x'.repeat(20)).repeat(200),
    ('..' + '/'.repeat(10)).repeat(400),
    'uiapi' + ' '.repeat(MAX - 10) + 'edge',
  ];
  const re = new RegExp(pattern, 'i');
  for (const input of inputs) re.test(input.slice(0, MAX));
`;
