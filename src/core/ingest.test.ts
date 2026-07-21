import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
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
});
