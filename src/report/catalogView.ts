import { egress } from '../sanitizer/egress.js';
import type { Rule } from '../types.js';

/**
 * Human-readable listing of the detection catalog, grouped by class.
 * Every rule field is routed through egress before display.
 */
export function renderCatalog(rules: readonly Rule[], family?: string): string {
  const filtered = family
    ? rules.filter((r) => r.family.toLowerCase() === family.toLowerCase())
    : rules;

  if (filtered.length === 0) {
    return family
      ? `No rules in family "${egress(family)}". Run "sfelf-triage catalog" to see all families.`
      : 'No rules in catalog.';
  }

  const ordered = [...filtered].sort(
    (a, b) => Number(a.sfExploitable) - Number(b.sfExploitable) || a.family.localeCompare(b.family),
  );

  const lines: string[] = [];
  let lastClass: boolean | null = null;
  for (const r of ordered) {
    if (r.sfExploitable !== lastClass) {
      if (lines.length > 0) lines.push('');
      lines.push(
        r.sfExploitable
          ? 'Class 2 — Salesforce guest/community abuse (data-exploitable):'
          : 'Class 1 — generic web-exploit probes (scanner noise on this platform):',
      );
      lastClass = r.sfExploitable;
    }
    lines.push(`  ${egress(r.id).padEnd(18)} ${egress(r.family).padEnd(24)} ${egress(r.note)}`);
  }

  lines.push('');
  lines.push(
    `${filtered.length} rule(s). Class-2 (sfExploitable) matches weigh toward LIKELY_ABUSE; ` +
      'Class-1 alone reads as an automated scan.',
  );
  return lines.join('\n');
}

/**
 * The catalog as data.
 *
 * `catalog` exists so the tool can explain its own coverage; the prose form serves an
 * analyst and defeats anything that needs to reason over the rule set — a coverage
 * check, a diff between versions, an agent deciding whether a family is handled here
 * or belongs in forensics-db. The rules are our own constants, not untrusted input, and
 * JSON.stringify escapes control characters itself, so no egress pass is needed.
 */
export function renderCatalogJson(rules: readonly Rule[], family?: string): string {
  const filtered = family
    ? rules.filter((r) => r.family.toLowerCase() === family.toLowerCase())
    : rules;

  return JSON.stringify(
    {
      family: family ?? null,
      count: filtered.length,
      rules: filtered,
    },
    null,
    2,
  );
}
