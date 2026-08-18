import { describe, it, expect } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { DEFAULT_LIMITS, LimitReport } from '../limits.js';
import { ingestFile } from './ingest.js';

const here = dirname(fileURLToPath(import.meta.url));

describe('ingest', () => {
  it('streams rows and keeps a quoted embedded-newline field as one record', async () => {
    const file = { path: join(here, '__fixtures__/crlf-sample.csv'), eventType: 'Sites', date: '2024-01-15' };
    const events = [];
    for await (const ev of ingestFile(file)) events.push(ev);
    expect(events).toHaveLength(2);            // NOT 3 — the embedded newline did not split the row
    expect(events[0].uri).toContain('Was-Header'); // decoded/captured intact
    expect(events[0].clientIp).toBe('203.0.113.10');
  });

  // MAX_FIELD in ingress clips a field only after csv-parse has assembled it, so without
  // a record ceiling one unterminated quote turns the rest of the file into a single
  // buffered record. csv-parse enforces that ceiling by ending the stream, which would
  // silently retire every later row — so the early end has to be detected and reported.
  it('reports a run as partial when an oversized record cuts the read short', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sfelf-record-'));
    try {
      const path = join(dir, 'Sites-2024-01-15.csv');
      await writeFile(
        path,
        'CLIENT_IP,URI\n' +
          '203.0.113.9,/first/\n' +
          `203.0.113.10,"${'a'.repeat(20_000)}"\n` +
          '203.0.113.11,/login/\n',
      );
      const report = new LimitReport();
      const events = [];
      for await (const ev of ingestFile(
        { path, eventType: 'Sites', date: '2024-01-15' },
        { ...DEFAULT_LIMITS, maxRecordSize: 4_096 },
        report,
      )) {
        events.push(ev);
      }
      // Rows before the oversized record survive; the ones after are lost to the
      // stream ending — which is exactly why this must not pass unreported.
      expect(events.map((e) => e.clientIp)).toEqual(['203.0.113.9']);
      expect(report.truncated).toBe(true);
      expect(report.toJSON().maxRecordSize).toBe(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reads a whole well-formed file without reporting truncation', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sfelf-record-ok-'));
    try {
      const path = join(dir, 'Sites-2024-01-15.csv');
      await writeFile(path, 'CLIENT_IP,URI\n203.0.113.9,/a/\n203.0.113.10,/b/\n');
      const report = new LimitReport();
      const events = [];
      for await (const ev of ingestFile({ path, eventType: 'Sites', date: '2024-01-15' }, DEFAULT_LIMITS, report)) {
        events.push(ev);
      }
      expect(events).toHaveLength(2);
      expect(report.truncated).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
