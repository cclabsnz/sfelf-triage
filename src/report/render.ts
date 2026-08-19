import Table from 'cli-table3';
import type { AnalysisReport } from '../core/analyze.js';
import { egress, mdCell } from '../sanitizer/egress.js';
import type { IpVerdict } from '../types.js';

function fams(v: IpVerdict, cell: (s: string) => string): string {
  return Object.entries(v.families)
    .sort((a, b) => b[1] - a[1])
    .map(([f, n]) => `${cell(f)}:${n}`)
    .join(', ');
}

/** `142` normally, `>=1000` when the per-IP ceiling made the count a floor. */
function uris(v: IpVerdict): string {
  return v.distinctUrisTruncated ? `>=${v.distinctUris}` : String(v.distinctUris);
}

export interface RenderOptions {
  /**
   * Include the scorer's per-IP reasons. Off by default: the verdict is the answer and
   * the table stays scannable, but "why did it say that" is the immediate next question
   * and the answer should not be reachable only by re-running with --json.
   */
  readonly why?: boolean;
}

function why(v: IpVerdict, cell: (s: string) => string): string {
  return v.reasons.map(cell).join('; ');
}

/**
 * The banner shown whenever a run cannot stand behind its own guarantees — either the
 * ReDoS-immune engine was not in use, or a ceiling truncated the input. Rendered into
 * every human-facing format so a degraded run cannot be mistaken for a clean one.
 */
function caveats(report: AnalysisReport): string[] {
  const out: string[] = [];
  if (report.engine !== 're2') {
    out.push(
      `DEGRADED — regex engine is "${report.engine}", not RE2: ${egress(report.degradedReason ?? 'unknown')}. ` +
        'Linear-time matching is not guaranteed; input caps are the only ReDoS bound. ' +
        'Use --require-re2 to fail instead of degrading.',
    );
  }
  const limitSummary = report.limits.summary();
  if (limitSummary) out.push(limitSummary);
  return out;
}

// renderJson intentionally bypasses egress: JSON.stringify already escapes every control
// character as a \uXXXX sequence, so no raw control byte can reach the terminal. Routing
// through egress would strip characters from JSON values, reducing fidelity of the
// machine-readable format without any security benefit.
export function renderJson(report: AnalysisReport): string {
  return JSON.stringify(
    {
      engine: report.engine,
      degradedReason: report.degradedReason,
      truncated: report.limits.truncated,
      limitsReached: report.limits.toJSON(),
      stats: report.stats,
      verdicts: report.verdicts,
    },
    null,
    2,
  );
}

export function renderTable(report: AnalysisReport, opts: RenderOptions = {}): string {
  const head = ['IP', 'Verdict', 'Reqs', 'Distinct URIs', 'sfHits', 'Families'];
  if (opts.why) head.push('Why');
  const t = new Table({ head, wordWrap: true });
  for (const v of report.verdicts) {
    const row = [
      egress(v.ip),
      egress(v.verdict),
      String(v.totalReqs),
      uris(v),
      String(v.sfExploitableHits),
      fams(v, egress),
    ];
    if (opts.why) row.push(why(v, egress));
    t.push(row);
  }
  const notes = caveats(report);
  return notes.length > 0 ? `${notes.join('\n')}\n\n${t.toString()}` : t.toString();
}

export function renderMarkdown(report: AnalysisReport, opts: RenderOptions = {}): string {
  const lines: string[] = [];
  for (const note of caveats(report)) lines.push(`> **${mdCell(note)}**`, '');
  lines.push(
    `| IP | Verdict | Reqs | Distinct URIs | sfHits | Confidence |${opts.why ? ' Why |' : ''}`,
    `|---|---|---|---|---|---|${opts.why ? '---|' : ''}`,
  );
  for (const v of report.verdicts) {
    lines.push(
      `| ${mdCell(v.ip)} | ${mdCell(v.verdict)} | ${v.totalReqs} | ${uris(v)} | ` +
        `${v.sfExploitableHits} | ${mdCell(v.confidence)} |` +
        (opts.why ? ` ${why(v, mdCell)} |` : ''),
    );
  }
  return lines.join('\n');
}
