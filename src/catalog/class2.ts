import type { Rule } from '../types.js';

/**
 * Salesforce-specific guest/community abuse patterns. sfExploitable=true — a match
 * here is behaviour that could touch real data on this platform, unlike Class 1.
 */
export const class2Rules: readonly Rule[] = [
  { id: 'c2-graphql-edges', family: 'Guest-GraphQL-bulk-read', source: 'custom', severity: 'high',
    target: 'query', pattern: String.raw`uiapi\b[\s\S]*\bedges\b`, sfExploitable: true,
    note: 'Guest GraphQL collection read (edges) — potential bulk record read.' },
  { id: 'c2-apex-action', family: 'Guest-Apex-controller', source: 'custom', severity: 'medium',
    target: 'action', pattern: String.raw`ApexActionController/ACTION\$execute`, sfExploitable: true,
    note: 'Guest invoked an Apex data controller (vs login-only framework actions).' },
  { id: 'c2-listview-recon', family: 'Guest-listview-recon', source: 'custom', severity: 'medium',
    target: 'query', pattern: String.raw`\bListView\b|\bQueriedEntities\b`, sfExploitable: true,
    note: 'Guest list-view / entity recon.' },
];
