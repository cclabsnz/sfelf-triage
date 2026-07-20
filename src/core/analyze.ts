import { discover } from './discover.js';
import { ingestFile } from './ingest.js';
import { Matcher } from './match.js';
import { correlate } from './correlate.js';
import { score } from './score.js';
import type { IpVerdict, MatchedEvent, SafeEvent } from '../types.js';

export async function analyze(dir: string): Promise<IpVerdict[]> {
  const files = await discover(dir);
  const matcher = new Matcher();
  const matched: MatchedEvent[] = [];
  const all: SafeEvent[] = [];
  for (const file of files) {
    for await (const ev of ingestFile(file)) {
      all.push(ev);
      matched.push(matcher.match(ev));
    }
  }
  const correlations = correlate(all);
  return score(matched, correlations);
}
