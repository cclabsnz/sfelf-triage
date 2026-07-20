import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discover } from './discover.js';

describe('discover', () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'sfelf-'));
    await writeFile(join(dir, 'Sites-2026-07-15.csv'), 'a\n');
    await writeFile(join(dir, 'AuraRequest-2026-07-15.csv'), 'a\n');
    await writeFile(join(dir, 'manifest.json'), '{}');
    await writeFile(join(dir, 'notes.txt'), 'x');
  });
  afterAll(async () => rm(dir, { recursive: true, force: true }));

  it('returns only well-named CSVs with parsed type + date', async () => {
    const files = await discover(dir);
    expect(files).toHaveLength(2);
    const sites = files.find(f => f.eventType === 'Sites')!;
    expect(sites.date).toBe('2026-07-15');
    expect(sites.path.endsWith('Sites-2026-07-15.csv')).toBe(true);
  });
});
