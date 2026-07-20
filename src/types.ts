export const VERDICTS = ['BENIGN_SCANNER', 'SUSPICIOUS', 'LIKELY_ABUSE'] as const;
export type Verdict = (typeof VERDICTS)[number];

/** Unique brand marking a value as having passed Sanitizer.ingress. */
export const brand: unique symbol = Symbol('SafeEvent');

export type EventType = string;
export type RawRow = Record<string, string>;

/** A single log request after sanitization. Only Sanitizer.ingress constructs this. */
export interface SafeEvent {
  readonly [brand]: true;
  readonly ts: number | null;          // epoch ms from TIMESTAMP_DERIVED
  readonly clientIp: string;
  readonly eventType: EventType;
  readonly userType: string | null;
  readonly method: string | null;
  readonly uri: string;                // URL-decoded, length-capped
  readonly query: string | null;       // GraphQL/SOQL text, length-capped
  readonly actionMessage: string | null;
  readonly requestId: string | null;
  readonly requestStatus: string | null;
  readonly isError: boolean | null;
  readonly responseSize: number | null;
  readonly rowsProcessed: number | null;
}

export type RuleTarget = 'uri' | 'query' | 'action' | 'header';

export interface Rule {
  readonly id: string;
  readonly family: string;
  readonly source: string;             // "CRS:<id>" | "custom"
  readonly severity: 'info' | 'low' | 'medium' | 'high';
  readonly target: RuleTarget;
  readonly pattern: string;            // regex source, run only via SafeMatcher
  readonly sfExploitable: boolean;
  readonly note: string;
}

export interface Match {
  readonly ruleId: string;
  readonly family: string;
  readonly sfExploitable: boolean;
  readonly severity: Rule['severity'];
  readonly target: RuleTarget;
}

export interface MatchedEvent {
  readonly event: SafeEvent;
  readonly matches: readonly Match[];
}

export interface IpVerdict {
  readonly ip: string;
  readonly verdict: Verdict;
  readonly reasons: readonly string[];
  readonly totalReqs: number;
  readonly distinctUris: number;
  readonly families: Readonly<Record<string, number>>;
  readonly sfExploitableHits: number;
  readonly allResponsesErrorOrCanned: boolean;
  readonly confidence: string;         // honesty note
}
