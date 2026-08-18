/**
 * Resource ceilings for the analysis pipeline.
 *
 * The input is hostile by definition (see docs/SECURITY.md), so every unbounded
 * accumulator is a denial-of-service primitive: an attacker who can shape traffic
 * into an org's EventLogFile can also shape the analyst's memory profile. Each
 * ceiling below bounds one accumulator.
 *
 * Nothing is ever truncated silently. When a ceiling is reached the pipeline
 * records it in a `LimitReport`, and every renderer surfaces it, so a partial
 * analysis can never be mistaken for a complete one.
 */
export interface Limits {
  /** Total rows ingested across all files. */
  readonly maxRows: number;
  /** CSV files discovered under the target directory. */
  readonly maxFiles: number;
  /** Directory recursion depth below the target directory. */
  readonly maxDepth: number;
  /** Distinct client IPs tracked. */
  readonly maxIps: number;
  /** Distinct URIs retained per IP (the count is reported as a floor once hit). */
  readonly maxUrisPerIp: number;
  /** Distinct response sizes retained per IP for the canned-page heuristic. */
  readonly maxResponseSizesPerIp: number;
  /** Correlation candidates (file reads + downloads) retained per IP. */
  readonly maxCorrelationEventsPerIp: number;
  /** Largest single CSV record csv-parse will assemble, in bytes. */
  readonly maxRecordSize: number;
}

export const DEFAULT_LIMITS: Limits = {
  maxRows: 5_000_000,
  maxFiles: 10_000,
  maxDepth: 16,
  maxIps: 200_000,
  maxUrisPerIp: 1_000,
  maxResponseSizesPerIp: 1_000,
  maxCorrelationEventsPerIp: 10_000,
  maxRecordSize: 1_048_576,
};

export type LimitName = keyof Limits;

/**
 * Records which ceilings were reached during a run.
 *
 * Holds the limits it was created with rather than taking them at render time: the
 * summary quotes the value that actually bit, and a caller cannot accidentally describe
 * a run using ceilings it was not run with.
 */
export class LimitReport {
  private readonly hit = new Map<LimitName, number>();

  constructor(private readonly limits: Limits = DEFAULT_LIMITS) {}

  /** Note that `name` was reached; counts how many times it bit. */
  reached(name: LimitName): void {
    this.hit.set(name, (this.hit.get(name) ?? 0) + 1);
  }

  get truncated(): boolean {
    return this.hit.size > 0;
  }

  /** Stable, serializable view: limit name -> number of times it bit. */
  toJSON(): Record<string, number> {
    return Object.fromEntries([...this.hit].sort((a, b) => a[0].localeCompare(b[0])));
  }

  /** One-line human summary, or null when the run was complete. */
  summary(): string | null {
    if (!this.truncated) return null;
    const parts = [...this.hit]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([name, n]) => `${name}=${this.limits[name]} (hit ${n}x)`);
    return `PARTIAL ANALYSIS — resource ceilings reached: ${parts.join(', ')}. ` +
      'Results below are a lower bound. Narrow the input (fewer days, one event type) and re-run.';
  }
}
