import Table from 'cli-table3';
import { egress } from '../sanitizer/egress.js';
import type { IpVerdict } from '../types.js';

function fams(v: IpVerdict): string {
  return Object.entries(v.families)
    .sort((a, b) => b[1] - a[1])
    .map(([f, n]) => `${egress(f)}:${n}`)
    .join(', ');
}

// renderJson intentionally bypasses egress: JSON.stringify already escapes all control
// characters (e.g. ESC -> \u001b, CR -> \r, NUL -> \u0000), so no raw control byte
// can reach the terminal. Routing through egress would strip characters from JSON values,
// reducing fidelity of the machine-readable format without any security benefit.
export function renderJson(verdicts: readonly IpVerdict[]): string {
  return JSON.stringify(verdicts, null, 2);
}

export function renderTable(verdicts: readonly IpVerdict[]): string {
  const t = new Table({ head: ['IP', 'Verdict', 'Reqs', 'Distinct URIs', 'sfHits', 'Families'] });
  for (const v of verdicts) {
    t.push([egress(v.ip), egress(v.verdict), String(v.totalReqs), String(v.distinctUris),
      String(v.sfExploitableHits), fams(v)]);
  }
  return t.toString();
}

export function renderMarkdown(verdicts: readonly IpVerdict[]): string {
  const lines = ['| IP | Verdict | Reqs | Distinct URIs | sfHits | Confidence |',
    '|---|---|---|---|---|---|'];
  for (const v of verdicts) {
    lines.push(`| ${egress(v.ip)} | ${egress(v.verdict)} | ${v.totalReqs} | ${v.distinctUris} | ` +
      `${v.sfExploitableHits} | ${egress(v.confidence)} |`);
  }
  return lines.join('\n');
}
