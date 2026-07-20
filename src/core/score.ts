import type { IpVerdict, MatchedEvent, Verdict } from '../types.js';
import type { Correlation } from './correlate.js';

interface Acc {
  total: number;
  uris: Set<string>;
  families: Record<string, number>;
  sfHits: number;
  matchedResponses: { isError: boolean | null; size: number | null }[];
}

/** Sizes seen ≥ 3 times are treated as canned platform pages, not data. */
function cannedSizes(resp: { size: number | null }[]): Set<number> {
  const counts = new Map<number, number>();
  for (const r of resp) if (r.size != null) counts.set(r.size, (counts.get(r.size) ?? 0) + 1);
  const set = new Set<number>();
  for (const [size, n] of counts) if (n >= 3) set.add(size);
  return set;
}

function allErrorOrCanned(resp: Acc['matchedResponses'], canned: Set<number>): boolean {
  if (resp.length === 0) return false;
  return resp.every(r => r.isError === true || (r.size != null && (r.size === 0 || canned.has(r.size))));
}

export function score(matched: readonly MatchedEvent[], correlations: readonly Correlation[]): IpVerdict[] {
  const byIp = new Map<string, Acc>();
  for (const me of matched) {
    const ip = me.event.clientIp;
    let a = byIp.get(ip);
    if (!a) { a = { total: 0, uris: new Set(), families: {}, sfHits: 0, matchedResponses: [] }; byIp.set(ip, a); }
    a.total += 1;
    a.uris.add(me.event.uri);
    if (me.matches.length > 0) {
      a.matchedResponses.push({ isError: me.event.isError, size: me.event.responseSize });
      for (const mt of me.matches) {
        a.families[mt.family] = (a.families[mt.family] ?? 0) + 1;
        if (mt.sfExploitable) a.sfHits += 1;
      }
    }
  }

  const corrIps = new Set(correlations.map(c => c.ip));
  const out: IpVerdict[] = [];
  for (const [ip, a] of byIp) {
    const canned = cannedSizes(a.matchedResponses.map(r => ({ size: r.size })));
    const cannedAll = allErrorOrCanned(a.matchedResponses, canned);
    const hasMatches = a.matchedResponses.length > 0;

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

    const confidence = verdict === 'LIKELY_ABUSE'
      ? 'Behavioural/exploitable signal present; confirm record return via forensics-db + guest access rights.'
      : 'No data-return signature observed; content not provable from EventLogFile alone.';

    out.push({
      ip, verdict, reasons,
      totalReqs: a.total, distinctUris: a.uris.size, families: a.families,
      sfExploitableHits: a.sfHits, allResponsesErrorOrCanned: cannedAll, confidence,
    });
  }
  return out.sort((x, y) => y.totalReqs - x.totalReqs);
}
