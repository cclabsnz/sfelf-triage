import { egress } from '../sanitizer/egress.js';
import { VERDICTS, type Verdict } from '../types.js';

const TEXT: Record<Verdict, string> = {
  BENIGN_SCANNER:
    'Class-1 probes only (Log4Shell / LFI / rwservlet etc. — inert on Salesforce) AND every ' +
    'matched response was an error or a canned platform page. An automated vulnerability scan, ' +
    'not a breach. No data access observed.',
  SUSPICIOUS:
    'Probe matches whose responses were NOT all error/canned — a real content-sized response ' +
    'came back on matched traffic. Not proven malicious, but worth a closer look.',
  LIKELY_ABUSE:
    'A Salesforce-exploitable (Class-2) match — e.g. a guest GraphQL bulk read — OR a ' +
    'read-then-download correlation. Behaviour that can touch real data on this platform.',
};

/** Explain one verdict, or all three when no argument is given. */
export function explainVerdict(verdict?: string): string {
  const targets: Verdict[] = verdict
    ? VERDICTS.includes(verdict as Verdict)
      ? [verdict as Verdict]
      : []
    : [...VERDICTS];

  if (verdict && targets.length === 0) {
    return `Unknown verdict "${egress(verdict)}". Known verdicts: ${VERDICTS.join(', ')}.`;
  }

  const lines: string[] = [];
  for (const v of targets) {
    lines.push(egress(v));
    lines.push('  ' + egress(TEXT[v]));
    lines.push('');
  }
  lines.push('Decision order: an sfExploitable match OR a read-then-download correlation → LIKELY_ABUSE;');
  lines.push('else matches with non-canned responses → SUSPICIOUS; else → BENIGN_SCANNER.');
  lines.push('');
  lines.push('Bounds, not proves: EventLogFile carries no response body, so a LIKELY_ABUSE verdict');
  lines.push('points you to the forensics-db layer + guest access rights to confirm data return —');
  lines.push('it is a lead to investigate, not proof of exfiltration.');
  return lines.join('\n');
}
