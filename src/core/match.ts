import { loadCatalog } from '../catalog/index.js';
import { SafeMatcher } from '../matcher/safeMatcher.js';
import type { Match, MatchedEvent, Rule, SafeEvent } from '../types.js';

function field(ev: SafeEvent, target: Rule['target']): string | null {
  switch (target) {
    case 'uri':
    case 'header':
      return ev.uri;
    case 'query':
      return ev.query;
    case 'action':
      return ev.actionMessage;
  }
}

export class Matcher {
  private readonly rules: readonly Rule[];
  private readonly matcher: SafeMatcher;

  constructor(rules: readonly Rule[] = loadCatalog(), matcher: SafeMatcher = new SafeMatcher()) {
    this.rules = rules;
    this.matcher = matcher;
  }

  match(ev: SafeEvent): MatchedEvent {
    const matches: Match[] = [];
    for (const r of this.rules) {
      const f = field(ev, r.target);
      if (f && this.matcher.test(r.pattern, f)) {
        matches.push({
          ruleId: r.id, family: r.family, sfExploitable: r.sfExploitable,
          severity: r.severity, target: r.target,
        });
      }
    }
    return { event: ev, matches };
  }
}
