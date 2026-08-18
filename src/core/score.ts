import { DEFAULT_LIMITS, LimitReport, type Limits } from '../limits.js';
import type { IpVerdict, MatchedEvent, Verdict } from '../types.js';
import type { Correlation } from './correlate.js';

/** A response size seen this many times is treated as a canned platform page, not data. */
const CANNED_REPEATS = 3;

/**
 * Per-IP state.
 *
 * Response bookkeeping is kept as frequency counts rather than a list of records: the
 * canned-page heuristic only ever asks "how often did this size occur" and "was every
 * non-error response either empty or canned", both of which counts answer exactly.
 * That turns per-IP memory from O(matched requests) into O(distinct response sizes).
 */
interface Acc {
  total: number;
  uris: Set<string>;
  urisTruncated: boolean;
  families: Map<string, number>;
  sfHits: number;
  matchedCount: number;
  /** size -> count, over every matched response that reported a size. */
  sizeCounts: Map<number, number>;
  /** size -> count, restricted to matched responses that were not errors. */
  nonErrorSizes: Map<number, number>;
  /** Matched non-error responses that reported no size at all. */
  nonErrorMissingSize: number;
  sizesTruncated: boolean;
}

function emptyAcc(): Acc {
  return {
    total: 0,
    uris: new Set(),
    urisTruncated: false,
    families: new Map(),
    sfHits: 0,
    matchedCount: 0,
    sizeCounts: new Map(),
    nonErrorSizes: new Map(),
    nonErrorMissingSize: 0,
    sizesTruncated: false,
  };
}

/**
 * Folds matched events into per-IP verdicts as they stream past.
 *
 * Nothing here retains an event. The pipeline used to buffer every `SafeEvent` and
 * every `MatchedEvent` for the whole run before scoring, which put peak memory in
 * proportion to total row count — the opposite of the constant-memory property the
 * ingest stage provides, and an out-of-memory failure on exactly the multi-gigabyte
 * incident exports this tool exists to triage. Peak memory now scales with distinct
 * IP cardinality, which the limits bound.
 */
export class ScoreAccumulator {
  private readonly byIp = new Map<string, Acc>();

  constructor(
    private readonly limits: Limits = DEFAULT_LIMITS,
    private readonly report: LimitReport = new LimitReport(),
  ) {}

  add(me: MatchedEvent): void {
    const ip = me.event.clientIp;
    let a = this.byIp.get(ip);
    if (!a) {
      if (this.byIp.size >= this.limits.maxIps) {
        this.report.reached('maxIps');
        return;
      }
      a = emptyAcc();
      this.byIp.set(ip, a);
    }

    a.total += 1;
    if (a.uris.size < this.limits.maxUrisPerIp) {
      a.uris.add(me.event.uri);
    } else if (!a.uris.has(me.event.uri)) {
      a.urisTruncated = true;
      this.report.reached('maxUrisPerIp');
    }

    if (me.matches.length === 0) return;

    a.matchedCount += 1;
    this.recordResponse(a, me.event.isError, me.event.responseSize);
    for (const mt of me.matches) {
      a.families.set(mt.family, (a.families.get(mt.family) ?? 0) + 1);
      if (mt.sfExploitable) a.sfHits += 1;
    }
  }

  private recordResponse(a: Acc, isError: boolean | null, size: number | null): void {
    if (size != null) {
      bump(a.sizeCounts, size, this.limits.maxResponseSizesPerIp, () => {
        a.sizesTruncated = true;
        this.report.reached('maxResponseSizesPerIp');
      });
    }
    if (isError === true) return;
    if (size == null) {
      a.nonErrorMissingSize += 1;
      return;
    }
    bump(a.nonErrorSizes, size, this.limits.maxResponseSizesPerIp, () => {
      a.sizesTruncated = true;
      this.report.reached('maxResponseSizesPerIp');
    });
  }

  finish(correlations: readonly Correlation[]): IpVerdict[] {
    const corrIps = new Set(correlations.map((c) => c.ip));
    const out: IpVerdict[] = [];

    for (const [ip, a] of this.byIp) {
      const cannedAll = this.allErrorOrCanned(a);
      const hasMatches = a.matchedCount > 0;

      let verdict: Verdict;
      const reasons: string[] = [];
      if (a.sfHits > 0 || corrIps.has(ip)) {
        verdict = 'LIKELY_ABUSE';
        if (a.sfHits > 0) reasons.push(`${a.sfHits} Salesforce-exploitable match(es)`);
        if (corrIps.has(ip)) reasons.push('read-then-download correlation');
      } else if (hasMatches && !cannedAll) {
        verdict = 'SUSPICIOUS';
        reasons.push('probe matches with non-canned responses — content return possible');
      } else {
        verdict = 'BENIGN_SCANNER';
        reasons.push('Class-1 probes only; responses were errors or canned platform pages');
      }
      if (a.sizesTruncated) {
        reasons.push('response-size detail truncated at the per-IP ceiling — canned-page test not conclusive');
      }

      const confidence =
        verdict === 'LIKELY_ABUSE'
          ? 'Behavioural/exploitable signal present; confirm record return via forensics-db + guest access rights.'
          : 'No data-return signature observed; content not provable from EventLogFile alone.';

      out.push({
        ip,
        verdict,
        reasons,
        totalReqs: a.total,
        distinctUris: a.uris.size,
        distinctUrisTruncated: a.urisTruncated,
        families: Object.fromEntries(a.families),
        sfExploitableHits: a.sfHits,
        allResponsesErrorOrCanned: cannedAll,
        confidence,
      });
    }

    return out.sort((x, y) => y.totalReqs - x.totalReqs);
  }

  /**
   * True when every matched response was an error, empty, or a repeated (canned) size.
   *
   * When size detail was truncated this returns false, which downgrades the IP toward
   * SUSPICIOUS rather than BENIGN_SCANNER. Incomplete evidence must not be able to
   * clear an IP: for a triage tool, over-flagging costs an analyst a second look, while
   * under-flagging is how a real intrusion gets filed as scanner noise.
   */
  private allErrorOrCanned(a: Acc): boolean {
    if (a.matchedCount === 0) return false;
    if (a.sizesTruncated) return false;
    if (a.nonErrorMissingSize > 0) return false;
    for (const [size, _count] of a.nonErrorSizes) {
      if (size === 0) continue;
      if ((a.sizeCounts.get(size) ?? 0) >= CANNED_REPEATS) continue;
      return false;
    }
    return true;
  }
}

function bump(m: Map<number, number>, key: number, cap: number, onFull: () => void): void {
  const existing = m.get(key);
  if (existing !== undefined) {
    m.set(key, existing + 1);
    return;
  }
  if (m.size >= cap) {
    onFull();
    return;
  }
  m.set(key, 1);
}

/** Batch convenience wrapper over {@link ScoreAccumulator}. */
export function score(
  matched: readonly MatchedEvent[],
  correlations: readonly Correlation[],
): IpVerdict[] {
  const acc = new ScoreAccumulator();
  for (const me of matched) acc.add(me);
  return acc.finish(correlations);
}
