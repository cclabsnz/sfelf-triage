import { DEFAULT_LIMITS, LimitReport, type Limits } from '../limits.js';
import type { Engine } from '../matcher/safeMatcher.js';
import { SafeMatcher } from '../matcher/safeMatcher.js';
import type { IpVerdict } from '../types.js';
import { Correlator, DEFAULT_WINDOW_MS } from './correlate.js';
import { discover } from './discover.js';
import { ingestFile } from './ingest.js';
import { Matcher } from './match.js';
import { ScoreAccumulator } from './score.js';

/**
 * Everything a caller needs to judge how much to trust a run: the verdicts, which
 * regex engine actually produced them, and whether any resource ceiling truncated
 * the input. A bare verdict list cannot express "these results are partial" or
 * "the ReDoS-immune engine was not in use", and both change how findings should be read.
 */
export interface AnalysisReport {
  readonly verdicts: IpVerdict[];
  /** Regex engine used for every match in this run. */
  readonly engine: Engine;
  /** Non-null exactly when `engine === 'js'`: why RE2 was unavailable. */
  readonly degradedReason: string | null;
  readonly limits: LimitReport;
  readonly stats: {
    readonly files: number;
    readonly rows: number;
  };
}

export interface AnalyzeOptions {
  readonly limits?: Limits;
  readonly windowMs?: number;
  readonly matcher?: SafeMatcher;
}

/**
 * Triage every EventLogFile CSV under `dir`.
 *
 * Single streaming pass: each row is sanitized, matched, folded into the per-IP score
 * accumulator and offered to the correlator, then dropped. No stage retains the event
 * stream, so peak memory tracks distinct-IP cardinality rather than total rows.
 */
export async function analyze(dir: string, opts: AnalyzeOptions = {}): Promise<AnalysisReport> {
  const limits = opts.limits ?? DEFAULT_LIMITS;
  const report = new LimitReport(limits);
  const safeMatcher = opts.matcher ?? new SafeMatcher();

  const files = await discover(dir, limits, report);
  const matcher = new Matcher(undefined, safeMatcher);
  const scorer = new ScoreAccumulator(limits, report);
  const correlator = new Correlator(opts.windowMs ?? DEFAULT_WINDOW_MS, limits, report);

  let rows = 0;
  outer: for (const file of files) {
    for await (const ev of ingestFile(file, limits, report)) {
      if (rows >= limits.maxRows) {
        report.reached('maxRows');
        break outer;
      }
      rows += 1;
      correlator.add(ev);
      scorer.add(matcher.match(ev));
    }
  }

  return {
    verdicts: scorer.finish(correlator.finish()),
    engine: safeMatcher.engine,
    degradedReason: safeMatcher.degradedReason,
    limits: report,
    stats: { files: files.length, rows },
  };
}
