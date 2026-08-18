import type { AnalysisReport } from './core/analyze.js';
import { severityOf, VERDICTS, type IpVerdict, type Verdict } from './types.js';

/**
 * Exit codes for `--fail-on`.
 *
 * `INCONCLUSIVE` is deliberately distinct from `FINDINGS`. A gate has three answers, not
 * two: something was found, nothing was found, and the run was not complete enough to
 * say. Collapsing the third into "clean" is how a truncated analysis becomes a false
 * all-clear in a pipeline that only ever checks for a zero exit.
 */
export const GATE_EXIT = {
  FINDINGS: 3,
  INCONCLUSIVE: 4,
} as const;

export interface GateResult {
  readonly exitCode: 0 | typeof GATE_EXIT.FINDINGS | typeof GATE_EXIT.INCONCLUSIVE;
  /** Line for stderr explaining the outcome, or null when the gate passed cleanly. */
  readonly message: string | null;
  /** Verdicts at or above the threshold, most severe first. */
  readonly triggering: readonly IpVerdict[];
}

export function isVerdict(value: string): value is Verdict {
  return (VERDICTS as readonly string[]).includes(value);
}

/**
 * Decide whether a run should fail a pipeline at `threshold`.
 *
 * Findings win over incompleteness: if an IP already meets the threshold, the run has
 * answered the question and the truncation note is noise. Only when nothing was found
 * does completeness decide, because that is exactly the case where a missing row could
 * have changed the answer.
 *
 * A degraded regex engine is not treated as inconclusive. The JS fallback finds the same
 * matches as RE2; what it loses is the linear-time guarantee, which is a availability
 * property rather than a detection one. `--require-re2` is the control for that.
 */
export function evaluateGate(report: AnalysisReport, threshold: Verdict): GateResult {
  const min = severityOf(threshold);
  const triggering = report.verdicts
    .filter((v) => severityOf(v.verdict) >= min)
    .sort((a, b) => severityOf(b.verdict) - severityOf(a.verdict));

  if (triggering.length > 0) {
    const worst = triggering[0].verdict;
    return {
      exitCode: GATE_EXIT.FINDINGS,
      message:
        `${triggering.length} IP(s) at or above ${threshold} (most severe: ${worst}). ` +
        `Failing per --fail-on ${threshold}.`,
      triggering,
    };
  }

  if (report.limits.truncated) {
    return {
      exitCode: GATE_EXIT.INCONCLUSIVE,
      message:
        `no IP reached ${threshold}, but the run was truncated at a resource ceiling, ` +
        'so this is not a clean result. Narrow the input (fewer days, one event type) ' +
        'and re-run before treating it as a pass.',
      triggering,
    };
  }

  return { exitCode: 0, message: null, triggering };
}
