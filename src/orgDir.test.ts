import { describe, it, expect } from 'vitest';
import { resolveOrgDir, resolveTarget, EVENT_BASELINE } from './orgDir.js';

describe('resolveOrgDir', () => {
  it('resolves an org id to the sf-audit baseline directory', () => {
    const r = resolveOrgDir('00D000000000001EAA', '/home/a');
    expect(r).toEqual({ ok: true, dir: `/home/a/${EVENT_BASELINE}/00D000000000001EAA` });
  });

  it('accepts an alias directory name, not only a 15/18-char id', () => {
    const r = resolveOrgDir('prod-sandbox', '/home/a');
    expect(r.ok).toBe(true);
  });

  // The org id lands inside a filesystem path, so it is a traversal vector unless the
  // separator and the parent reference are both refused.
  it('refuses a path separator in the org id', () => {
    const r = resolveOrgDir('00D/../../etc', '/home/a');
    expect(r).toEqual({ ok: false, error: expect.stringMatching(/org id/i) });
  });

  it('refuses a bare parent reference', () => {
    expect(resolveOrgDir('..', '/home/a').ok).toBe(false);
  });

  it('refuses a backslash separator', () => {
    expect(resolveOrgDir('00D\\evil', '/home/a').ok).toBe(false);
  });

  it('refuses a leading dot, which would name a hidden sibling', () => {
    expect(resolveOrgDir('.ssh', '/home/a').ok).toBe(false);
  });

  it('refuses an empty org id', () => {
    expect(resolveOrgDir('', '/home/a').ok).toBe(false);
  });

  it('refuses a NUL byte', () => {
    expect(resolveOrgDir('00D\0x', '/home/a').ok).toBe(false);
  });
});

describe('resolveTarget', () => {
  it('passes a directory argument through unchanged', () => {
    expect(resolveTarget({ dir: './logs', home: '/home/a' })).toEqual({ ok: true, dir: './logs' });
  });

  it('expands --org into the baseline directory', () => {
    const r = resolveTarget({ org: '00D000000000001EAA', home: '/home/a' });
    expect(r).toEqual({ ok: true, dir: `/home/a/${EVENT_BASELINE}/00D000000000001EAA` });
  });

  it('refuses both at once rather than silently preferring one', () => {
    const r = resolveTarget({ dir: './logs', org: '00D000000000001EAA', home: '/home/a' });
    expect(r).toEqual({ ok: false, error: expect.stringMatching(/both|either/i) });
  });

  it('refuses neither, naming what to supply', () => {
    const r = resolveTarget({ home: '/home/a' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/--org/);
  });

  it('propagates an unsafe org id as an error', () => {
    expect(resolveTarget({ org: '../etc', home: '/home/a' }).ok).toBe(false);
  });
});
