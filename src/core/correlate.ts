import { DEFAULT_LIMITS, LimitReport, type Limits } from '../limits.js';
import type { SafeEvent } from '../types.js';

export interface Correlation {
  ip: string;
  kind: 'read-then-download';
  readTs: number;
  downloadTs: number;
}

const FILE_ENTITY = /ContentVersion|ContentDocument|Attachment/i;
const DOWNLOAD_TYPES = new Set(['ContentTransfer', 'ContentDistribution']);

export const DEFAULT_WINDOW_MS = 120_000;

/** Index of the first element >= target, or arr.length when there is none. */
function lowerBound(arr: readonly number[], target: number): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * Finds read-then-download sequences per IP, streaming.
 *
 * Retains only the two event kinds the pattern needs (file-object reads and content
 * downloads) rather than the full event stream, and caps each per-IP list, so memory
 * is bounded by distinct-IP cardinality instead of row count.
 *
 * Matching is a binary search over the sorted read timestamps. The previous linear
 * scan was O(reads x downloads) for a single IP, which made a single host issuing many
 * file reads and downloads — precisely the behaviour this rule exists to detect — able
 * to drive quadratic work in the analyzer.
 */
export class Correlator {
  private readonly readsByIp = new Map<string, number[]>();
  private readonly downloadsByIp = new Map<string, number[]>();

  constructor(
    private readonly windowMs: number = DEFAULT_WINDOW_MS,
    private readonly limits: Limits = DEFAULT_LIMITS,
    private readonly report: LimitReport = new LimitReport(),
  ) {}

  add(ev: SafeEvent): void {
    if (ev.ts == null) return;
    if (DOWNLOAD_TYPES.has(ev.eventType)) {
      this.push(this.downloadsByIp, ev.clientIp, ev.ts);
      return;
    }
    if (FILE_ENTITY.test(`${ev.query ?? ''} ${ev.uri}`)) {
      this.push(this.readsByIp, ev.clientIp, ev.ts);
    }
  }

  private push(index: Map<string, number[]>, ip: string, ts: number): void {
    let list = index.get(ip);
    if (!list) {
      if (index.size >= this.limits.maxIps) {
        this.report.reached('maxIps');
        return;
      }
      list = [];
      index.set(ip, list);
    }
    if (list.length >= this.limits.maxCorrelationEventsPerIp) {
      this.report.reached('maxCorrelationEventsPerIp');
      return;
    }
    list.push(ts);
  }

  finish(): Correlation[] {
    const out: Correlation[] = [];
    for (const [ip, downloads] of this.downloadsByIp) {
      const reads = this.readsByIp.get(ip);
      if (!reads || reads.length === 0) continue;
      reads.sort((a, b) => a - b);
      for (const downloadTs of downloads) {
        // A read qualifies when it lands in [downloadTs - windowMs, downloadTs].
        const i = lowerBound(reads, downloadTs - this.windowMs);
        if (i < reads.length && reads[i] <= downloadTs) {
          out.push({ ip, kind: 'read-then-download', readTs: reads[i], downloadTs });
        }
      }
    }
    return out;
  }
}

/** Batch convenience wrapper over {@link Correlator}. */
export function correlate(
  events: readonly SafeEvent[],
  windowMs = DEFAULT_WINDOW_MS,
): Correlation[] {
  const c = new Correlator(windowMs);
  for (const ev of events) c.add(ev);
  return c.finish();
}
