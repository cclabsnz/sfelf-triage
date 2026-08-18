import ipaddr from 'ipaddr.js';
import { brand, type EventType, type RawRow, type SafeEvent } from '../types.js';

export const MAX_FIELD = 8192;

/**
 * Client IP is the identity every verdict is keyed on, so it gets a tighter cap than
 * a payload field. No legitimate textual address exceeds 45 characters (IPv6 with a
 * mapped IPv4 suffix); the slack is for non-address markers some event types emit.
 */
export const MAX_IP_FIELD = 64;

/** Placeholder identity for rows that carry no client address at all. */
export const UNKNOWN_IP = 'unknown';

function cap(s: string | undefined): string {
  return (s ?? '').slice(0, MAX_FIELD);
}

/** Decode up to 3 layers of percent-encoding; never throw on malformed input. */
function decode(s: string): string {
  let out = s;
  for (let i = 0; i < 3; i++) {
    let next: string;
    try {
      next = decodeURIComponent(out);
    } catch {
      return out; // malformed — keep last good value
    }
    if (next === out) break;
    out = next;
  }
  return out;
}

function num(s: string | undefined): number | null {
  if (s === undefined || s === '') return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

function bool(s: string | undefined): boolean | null {
  if (s === undefined || s === '') return null;
  return s === '1' || s.toLowerCase() === 'true';
}

function str(s: string | undefined): string | null {
  const v = cap(s);
  return v === '' ? null : v;
}

function ts(row: RawRow): number | null {
  const raw = row.TIMESTAMP_DERIVED || row.TIMESTAMP;
  if (!raw) return null;
  const t = Date.parse(raw);
  return Number.isFinite(t) ? t : null;
}

/**
 * Canonicalize the client address so one host cannot appear as several identities.
 *
 * Verdicts, per-IP counters and every threshold in `score` are keyed on this string.
 * Without canonicalization the same host reaching an org over IPv4 and over an
 * IPv4-mapped IPv6 address (`::ffff:203.0.113.9`), or over an IPv6 address written
 * with different zero-compression (`2001:db8::1` vs `2001:0db8:0000::0001`), splits
 * into separate rows — halving every count an analyst reads and letting sustained
 * activity sit below the thresholds that would flag it.
 *
 * Only rewrites that are provably lossless are performed: IPv4-mapped IPv6 to its IPv4
 * form, and IPv6 spelling to one canonical spelling. Legacy IPv4 notations are
 * deliberately *not* interpreted, even though the parser understands them. `0203.0.113.9`
 * is octal for `131.0.113.9`, and `2130706433` is `127.0.0.1` — resolving those would put
 * an address in the report that appears nowhere in the log, which in an incident record
 * is a false attribution against a host that was never seen. Anything ambiguous is kept
 * exactly as the log wrote it, so the report can always be reconciled with its source.
 *
 * Values that are not addresses at all are preserved verbatim (length-capped) for the
 * same reason: some event types emit markers rather than addresses.
 */
export function normalizeIp(raw: string | undefined): string {
  const trimmed = (raw ?? '').trim().slice(0, MAX_IP_FIELD);
  if (trimmed === '') return UNKNOWN_IP;

  // Unambiguous dotted-decimal IPv4 is already canonical. isValidFourPartDecimal is the
  // check that rejects the octal / hex / integer spellings.
  if (ipaddr.IPv4.isValidFourPartDecimal(trimmed)) return trimmed;

  if (ipaddr.IPv6.isValid(trimmed)) {
    const v6 = ipaddr.IPv6.parse(trimmed);
    // Collapse a mapped address only when the log wrote its embedded IPv4 part as
    // unambiguous dotted-decimal (`::ffff:203.0.113.9`). Hex-packed and zero-prefixed
    // spellings stay in IPv6 form: they name the same host, but rewriting them would
    // again print an address the log does not contain.
    if (v6.isIPv4MappedAddress()) {
      const embedded = trimmed.slice(trimmed.lastIndexOf(':') + 1);
      if (ipaddr.IPv4.isValidFourPartDecimal(embedded)) return v6.toIPv4Address().toString();
    }
    return v6.toNormalizedString();
  }

  return trimmed; // ambiguous or not an address — keep as an opaque identity
}

export function ingress(row: RawRow, eventType: EventType): SafeEvent {
  return {
    [brand]: true,
    ts: ts(row),
    clientIp: normalizeIp(row.CLIENT_IP),
    eventType,
    userType: str(row.USER_TYPE),
    method: str(row.HTTP_METHOD ?? row.METHOD ?? row.REQUEST_METHOD),
    uri: cap(decode(cap(row.URI))),
    query: str(row.QUERY ? decode(cap(row.QUERY)) : undefined),
    actionMessage: str(row.ACTION_MESSAGE ? cap(row.ACTION_MESSAGE) : undefined),
    requestId: str(row.REQUEST_ID),
    requestStatus: str(row.REQUEST_STATUS),
    isError: bool(row.IS_ERROR),
    responseSize: num(row.RESPONSE_SIZE),
    rowsProcessed: num(row.ROWS_PROCESSED),
  };
}
