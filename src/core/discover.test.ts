import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
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

  it('returns only well-named CSVs with parsed type + date (flat layout)', async () => {
    const files = await discover(dir);
    expect(files).toHaveLength(2);
    const sites = files.find(f => f.eventType === 'Sites')!;
    expect(sites.date).toBe('2026-07-15');
    expect(sites.path.endsWith('Sites-2026-07-15.csv')).toBe(true);
  });

  it('reads the sf-audit plugin nested layout <EventType>/<date>-<Id>.csv', async () => {
    const orgDir = await mkdtemp(join(tmpdir(), 'sfelf-nested-'));
    await mkdir(join(orgDir, 'Sites'), { recursive: true });
    await mkdir(join(orgDir, '_manifests'), { recursive: true });
    await writeFile(join(orgDir, 'Sites', '2026-07-15-0AT000000000001.csv'), 'a\n');
    await writeFile(join(orgDir, '_manifests', 'manifest-123.json'), '{}');
    try {
      const files = await discover(orgDir);
      expect(files).toHaveLength(1); // the _manifests JSON is ignored
      expect(files[0].eventType).toBe('Sites');
      expect(files[0].date).toBe('2026-07-15');
    } finally {
      await rm(orgDir, { recursive: true, force: true });
    }
  });
});
