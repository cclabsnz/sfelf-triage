import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

/**
 * These exercise the CLI as a user meets it, by running the built binary.
 *
 * The unit suites cover each piece in isolation; what they cannot cover is the wiring —
 * which flag reaches which renderer, what lands on stdout versus stderr, and the exit
 * code. Those are the tool's actual contract with a pipeline, and until now they were
 * only checked by a shell block in CI, which never runs on a developer's machine.
 */
const CLI = resolve('dist/cli.js');
const BENIGN = resolve('src/core/__fixtures__/benign');

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

function run(...args: string[]): Promise<Run> {
  return new Promise((res) => {
    execFile('node', [CLI, ...args], { encoding: 'utf8' }, (err, stdout, stderr) => {
      const code = err && typeof (err as { code?: unknown }).code === 'number'
        ? (err as { code: number }).code
        : 0;
      res({ code, stdout, stderr });
    });
  });
}

let scratch: string;

beforeAll(async () => {
  // The built binary is the subject, so build it rather than assume a fresh dist/.
  await new Promise<void>((res, rej) => {
    execFile('node', ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'], (err, _o, se) =>
      err ? rej(new Error(`build failed: ${se}`)) : res(),
    );
  });
  scratch = await mkdtemp(join(tmpdir(), 'sfelf-cli-'));
}, 120_000);

afterAll(async () => rm(scratch, { recursive: true, force: true }));

// A stale native binding is a legitimate state of a developer's checkout — it is the
// state `doctor` exists to name — so these assert that the diagnosis is internally
// consistent and correctly scored, not that the machine running them is healthy.
describe('cli: doctor', () => {
  it('reports the running Node, the engine and the ceilings', async () => {
    const r = await run('doctor');
    expect(r.stdout).toMatch(/status:\s+(OK|DEGRADED)/);
    expect(r.stdout).toContain(process.version);
    expect(r.stdout).toContain('Regex engine');
    expect(r.stdout).toContain('maxRows');
  });

  it('exits 0 when healthy and 2 when degraded, matching --require-re2', async () => {
    const [text, json] = await Promise.all([run('doctor'), run('doctor', '--json')]);
    const healthy = JSON.parse(json.stdout).status === 'ok';
    expect(text.code).toBe(healthy ? 0 : 2);
  });

  it('emits the same diagnosis as JSON', async () => {
    const out = JSON.parse((await run('doctor', '--json')).stdout);
    expect(out.node.version).toBe(process.version);
    expect(out.node.supported).toBe(true);
    expect(['re2', 'js']).toContain(out.engine.name);
    // status is exactly "RE2 loaded AND Node in range" — nothing else may make it ok.
    expect(out.status).toBe(out.engine.name === 're2' && out.node.supported ? 'ok' : 'degraded');
  });

  it('offers a remedy exactly when the engine is degraded', async () => {
    const out = JSON.parse((await run('doctor', '--json')).stdout);
    expect(out.engine.remedy === null).toBe(out.engine.name === 're2');
  });
});

describe('cli: analyze input forms', () => {
  it('accepts a single CSV file, not only a directory', async () => {
    const r = await run('analyze', join(BENIGN, 'Sites-2024-01-15.csv'), '--json');
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).stats.files).toBe(1);
  });

  it('names the CSVs it rejected, and why, instead of only "none found"', async () => {
    const dir = await mkdtemp(join(scratch, 'bad-'));
    await writeFile(join(dir, 'Sites_2024-01-15.csv'), 'a\n');
    await writeFile(join(dir, 'EventLogFile.csv'), 'a\n');
    const r = await run('analyze', dir);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('Sites_2024-01-15.csv');
    expect(r.stderr).toMatch(/underscore/i);
    expect(r.stderr).toContain('EventLogFile.csv');
    expect(r.stderr).toMatch(/date/i);
  });

  it('still explains an empty directory', async () => {
    const dir = await mkdtemp(join(scratch, 'empty-'));
    const r = await run('analyze', dir);
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/no EventLogFile CSVs/i);
  });
});

describe('cli: --org', () => {
  it('refuses an org id that would escape the baseline directory', async () => {
    const r = await run('analyze', '--org', '../../etc');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/org id/i);
  });

  it('refuses a directory and --org together', async () => {
    const r = await run('analyze', BENIGN, '--org', '00D000000000001EAA');
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/not both/i);
  });

  it('names both ways to supply logs when given neither', async () => {
    const r = await run('analyze');
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('--org');
  });

  it('reports the resolved baseline path when the org has no logs', async () => {
    const r = await run('analyze', '--org', 'no-such-org-dir');
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('event-baseline');
  });
});

describe('cli: --why', () => {
  it('adds the scorer reasons to the table', async () => {
    const r = await run('analyze', BENIGN, '--why');
    expect(r.stdout).toContain('Why');
    expect(r.stdout).toMatch(/Class-1 probes only/);
  });

  it('leaves the default table unchanged', async () => {
    const r = await run('analyze', BENIGN);
    expect(r.stdout).not.toContain('Why');
  });
});

describe('cli: --out', () => {
  it('writes the report to a file and keeps stdout clean', async () => {
    const out = join(scratch, 'report.json');
    const r = await run('analyze', BENIGN, '--json', '--out', out);
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe('');
    expect(JSON.parse(await readFile(out, 'utf8')).verdicts.length).toBeGreaterThan(0);
  });

  it('writes markdown to a file too', async () => {
    const out = join(scratch, 'report.md');
    await run('analyze', BENIGN, '--md', '--out', out);
    expect(await readFile(out, 'utf8')).toContain('| IP |');
  });

  it('fails with a clear error when the path is unwritable', async () => {
    const r = await run('analyze', BENIGN, '--json', '--out', join(scratch, 'nope', 'x.json'));
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/could not write/i);
  });
});

describe('cli: machine-readable self-documentation', () => {
  it('emits the catalog as JSON', async () => {
    const out = JSON.parse((await run('catalog', '--json')).stdout);
    expect(out.count).toBeGreaterThan(0);
    expect(out.rules[0]).toHaveProperty('sfExploitable');
  });

  it('emits the verdict logic as JSON', async () => {
    const out = JSON.parse((await run('explain', '--json')).stdout);
    expect(out.verdicts).toHaveLength(3);
    expect(out.decisionOrder.length).toBeGreaterThan(0);
  });

  it('exits 1 on an unknown verdict rather than printing a non-answer as success', async () => {
    const r = await run('explain', 'NOPE');
    expect(r.code).toBe(1);
  });
});
