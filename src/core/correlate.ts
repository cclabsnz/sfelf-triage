import type { SafeEvent } from '../types.js';

export interface Correlation {
  ip: string;
  kind: 'read-then-download';
  readTs: number;
  downloadTs: number;
}

const FILE_ENTITY = /ContentVersion|ContentDocument|Attachment/i;
const DOWNLOAD_TYPES = new Set(['ContentTransfer', 'ContentDistribution']);

export function correlate(events: readonly SafeEvent[], windowMs = 120_000): Correlation[] {
  // Bounded index: only file-object reads, keyed by IP, kept in time order.
  const readsByIp = new Map<string, number[]>();
  for (const ev of events) {
    if (ev.ts == null) continue;
    const text = `${ev.query ?? ''} ${ev.uri}`;
    if (FILE_ENTITY.test(text) && !DOWNLOAD_TYPES.has(ev.eventType)) {
      (readsByIp.get(ev.clientIp) ?? readsByIp.set(ev.clientIp, []).get(ev.clientIp)!).push(ev.ts);
    }
  }
  for (const list of readsByIp.values()) list.sort((a, b) => a - b);

  const out: Correlation[] = [];
  for (const ev of events) {
    if (ev.ts == null || !DOWNLOAD_TYPES.has(ev.eventType)) continue;
    const reads = readsByIp.get(ev.clientIp);
    if (!reads) continue;
    const hit = reads.find(r => ev.ts! - r >= 0 && ev.ts! - r <= windowMs);
    if (hit !== undefined) {
      out.push({ ip: ev.clientIp, kind: 'read-then-download', readTs: hit, downloadTs: ev.ts });
    }
  }
  return out;
}
