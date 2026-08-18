import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DEFAULT_LIMITS, LimitReport } from '../limits.js';
import { discover } from './discover.js';

describe('discover', () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'sfelf-'));
    await writeFile(join(dir, 'Sites-2024-01-15.csv'), 'a\n');
    await writeFile(join(dir, 'AuraRequest-2024-01-15.csv'), 'a\n');
    await writeFile(join(dir, 'manifest.json'), '{}');
    await writeFile(join(dir, 'notes.txt'), 'x');
  });
  afterAll(async () => rm(dir, { recursive: true, force: true }));

  it('returns only well-named CSVs with parsed type + date (flat layout)', async () => {
    const files = await discover(dir);
    expect(files).toHaveLength(2);
    const sites = files.find(f => f.eventType === 'Sites')!;
    expect(sites.date).toBe('2024-01-15');
    expect(sites.path.endsWith('Sites-2024-01-15.csv')).toBe(true);
  });

  it('reads the sf-audit plugin nested layout <EventType>/<date>-<Id>.csv', async () => {
    const orgDir = await mkdtemp(join(tmpdir(), 'sfelf-nested-'));
    await mkdir(join(orgDir, 'Sites'), { recursive: true });
    await mkdir(join(orgDir, '_manifests'), { recursive: true });
    await writeFile(join(orgDir, 'Sites', '2024-01-15-0AT000000000001.csv'), 'a\n');
    await writeFile(join(orgDir, '_manifests', 'manifest-123.json'), '{}');
    try {
      const files = await discover(orgDir);
      expect(files).toHaveLength(1); // the _manifests JSON is ignored
      expect(files[0].eventType).toBe('Sites');
      expect(files[0].date).toBe('2024-01-15');
    } finally {
      await rm(orgDir, { recursive: true, force: true });
    }
  });
});

// A log directory is attacker-adjacent: it is routinely unpacked from an archive
// supplied by whoever is under investigation. Traversal has to stay inside it and
// terminate, whatever the tree looks like.
describe('discover: traversal confinement', () => {
  let root: string;
  let outside: string;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'sfelf-confine-'));
    outside = await mkdtemp(join(tmpdir(), 'sfelf-outside-'));
    await writeFile(join(outside, 'Secrets-2024-01-15.csv'), 'a\n');
    await writeFile(join(root, 'Sites-2024-01-15.csv'), 'a\n');
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  it('does not follow a symlinked directory out of the target tree', async () => {
    await symlink(outside, join(root, 'escape'), 'dir');
    const files = await discover(root);
    expect(files.map((f) => f.eventType)).toEqual(['Sites']);
  });

  it('does not follow a symlinked file into the target tree', async () => {
    await symlink(join(outside, 'Secrets-2024-01-15.csv'), join(root, 'Linked-2024-01-15.csv'));
    const files = await discover(root);
    expect(files.map((f) => f.eventType)).toEqual(['Sites']);
  });

  it('does not loop forever on a symlink cycle', async () => {
    const cyclic = await mkdtemp(join(tmpdir(), 'sfelf-cycle-'));
    try {
      await mkdir(join(cyclic, 'a'), { recursive: true });
      await symlink(cyclic, join(cyclic, 'a', 'loop'), 'dir');
      await writeFile(join(cyclic, 'Sites-2024-01-15.csv'), 'a\n');
      await expect(discover(cyclic)).resolves.toHaveLength(1);
    } finally {
      await rm(cyclic, { recursive: true, force: true });
    }
  });

  it('stops descending at the depth ceiling and records it', async () => {
    const deep = await mkdtemp(join(tmpdir(), 'sfelf-deep-'));
    try {
      const nested = join(deep, ...Array.from({ length: 6 }, (_, i) => `d${i}`));
      await mkdir(join(nested, 'Sites'), { recursive: true });
      await writeFile(join(nested, 'Sites', '2024-01-15-0AT0000000001.csv'), 'a\n');

      const report = new LimitReport();
      const files = await discover(deep, { ...DEFAULT_LIMITS, maxDepth: 2 }, report);
      expect(files).toHaveLength(0);
      expect(report.toJSON().maxDepth).toBeGreaterThan(0);

      // The same tree is found when the ceiling allows it — the cap is what stopped it.
      await expect(discover(deep)).resolves.toHaveLength(1);
    } finally {
      await rm(deep, { recursive: true, force: true });
    }
  });

  it('stops at the file ceiling and records it rather than truncating silently', async () => {
    const many = await mkdtemp(join(tmpdir(), 'sfelf-many-'));
    try {
      for (let i = 0; i < 8; i++) {
        await writeFile(join(many, `Sites-2024-01-${String(10 + i)}.csv`), 'a\n');
      }
      const report = new LimitReport();
      const files = await discover(many, { ...DEFAULT_LIMITS, maxFiles: 3 }, report);
      expect(files).toHaveLength(3);
      expect(report.truncated).toBe(true);
      expect(report.summary()).toContain('PARTIAL ANALYSIS');
    } finally {
      await rm(many, { recursive: true, force: true });
    }
  });
});
