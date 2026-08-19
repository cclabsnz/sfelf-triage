import type { Limits } from '../limits.js';
import type { Engine } from '../matcher/safeMatcher.js';
import { egress } from '../sanitizer/egress.js';

export interface DoctorInput {
  /** `process.version`, e.g. `v22.22.2`. */
  readonly nodeVersion: string;
  /** The `engines.node` range this build declares. */
  readonly supportedRange: string;
  readonly engine: Engine;
  readonly degradedReason: string | null;
  readonly limits: Limits;
}

export type DoctorStatus = 'ok' | 'degraded';

/** What to do about a JS-fallback engine. Kept next to the diagnosis, not in a doc. */
export const RE2_REMEDY =
  'rebuild the native binding with "pnpm rebuild re2"; if that fails, check that the ' +
  'running Node major matches the one the binding was built for';

const CARET = /^\^(\d+)\.(\d+)\.(\d+)$/;
const GTE = /^>=(\d+)\.(\d+)\.(\d+)$/;
const VERSION = /^v?(\d+)\.(\d+)\.(\d+)/;

function cmp(a: readonly number[], b: readonly number[]): number {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

/**
 * Evaluate `version` against the small subset of range syntax this package actually
 * declares: `^X.Y.Z` and `>=X.Y.Z` clauses joined by `||`.
 *
 * Returns `null` — not `false` — for anything it does not recognize. A wrong
 * "unsupported Node" verdict is worse than no verdict: it sends an analyst reinstalling
 * a runtime to fix a problem that is not there. Declining to answer keeps `doctor`
 * trustworthy when the range outgrows this parser.
 */
export function satisfiesRange(version: string, range: string): boolean | null {
  const v = VERSION.exec(version);
  if (!v) return null;
  const have = [Number(v[1]), Number(v[2]), Number(v[3])];

  let ok = false;
  for (const raw of range.split('||')) {
    const clause = raw.trim();
    const caret = CARET.exec(clause);
    if (caret) {
      const floor = [Number(caret[1]), Number(caret[2]), Number(caret[3])];
      if (have[0] === floor[0] && cmp(have, floor) >= 0) ok = true;
      continue;
    }
    const gte = GTE.exec(clause);
    if (gte) {
      const floor = [Number(gte[1]), Number(gte[2]), Number(gte[3])];
      if (cmp(have, floor) >= 0) ok = true;
      continue;
    }
    return null; // an unrecognized clause makes the whole answer unreliable
  }
  return ok;
}

/**
 * Whether this installation can stand behind its own guarantees.
 *
 * An unverifiable Node range is not degradation — see {@link satisfiesRange}. A JS
 * regex engine is, because the linear-time matching the tool advertises is gone.
 */
export function doctorStatus(input: DoctorInput): DoctorStatus {
  if (input.engine !== 're2') return 'degraded';
  if (satisfiesRange(input.nodeVersion, input.supportedRange) === false) return 'degraded';
  return 'ok';
}

/**
 * A one-command answer to "is this install healthy, and if not what do I run".
 *
 * The information was previously spread across a stderr warning that only appears
 * mid-analysis, a README section, and the source of `limits.ts`.
 */
export function renderDoctor(input: DoctorInput): string {
  const supported = satisfiesRange(input.nodeVersion, input.supportedRange);
  const status = doctorStatus(input);
  const lines: string[] = [];

  lines.push(`status:  ${status.toUpperCase()}`);
  lines.push('');
  lines.push('Node');
  lines.push(`  running:   ${egress(input.nodeVersion)}`);
  lines.push(`  supported: ${egress(input.supportedRange)}`);
  lines.push(
    `  verdict:   ${
      supported === null
        ? 'not verified — the declared range uses syntax this check does not parse'
        : supported
          ? 'in range'
          : 'OUT OF RANGE — install a supported Node and reinstall dependencies'
    }`,
  );
  lines.push('');
  lines.push('Regex engine');
  lines.push(`  engine:    ${egress(input.engine)}`);
  if (input.engine === 're2') {
    lines.push('  verdict:   RE2 — matching is linear-time and ReDoS-immune');
  } else {
    lines.push(`  reason:    ${egress(input.degradedReason ?? 'unknown')}`);
    lines.push('  verdict:   DEGRADED — ReDoS immunity is not guaranteed; field caps are the only bound');
    lines.push(`  fix:       ${RE2_REMEDY}`);
    lines.push('             pass --require-re2 to make this state fatal in a pipeline');
  }
  lines.push('');
  lines.push('Resource ceilings (src/limits.ts)');
  for (const [name, value] of Object.entries(input.limits)) {
    lines.push(`  ${name.padEnd(26)} ${value}`);
  }
  return lines.join('\n');
}

/** The same diagnosis as data, so a pipeline can assert on it. */
export function renderDoctorJson(input: DoctorInput): string {
  return JSON.stringify(
    {
      status: doctorStatus(input),
      node: {
        version: input.nodeVersion,
        supportedRange: input.supportedRange,
        supported: satisfiesRange(input.nodeVersion, input.supportedRange),
      },
      engine: {
        name: input.engine,
        degradedReason: input.degradedReason,
        remedy: input.engine === 're2' ? null : RE2_REMEDY,
      },
      limits: input.limits,
    },
    null,
    2,
  );
}
