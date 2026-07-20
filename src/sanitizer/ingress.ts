import { brand, type EventType, type RawRow, type SafeEvent } from '../types.js';

export const MAX_FIELD = 8192;

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

export function ingress(row: RawRow, eventType: EventType): SafeEvent {
  return {
    [brand]: true,
    ts: ts(row),
    clientIp: cap(row.CLIENT_IP),
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
