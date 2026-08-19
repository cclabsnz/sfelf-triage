import { describe, it, expect } from 'vitest';
import { renderCatalog, renderCatalogJson } from './catalogView.js';
import { loadCatalog } from '../catalog/index.js';

describe('renderCatalog', () => {
  const rules = loadCatalog();

  it('lists rules under both class headers', () => {
    const out = renderCatalog(rules);
    expect(out).toContain('Class 1');
    expect(out).toContain('Class 2');
    expect(out).toContain('Log4Shell');
    expect(out).toContain('c1-log4shell');
  });

  it('filters to a single family', () => {
    const out = renderCatalog(rules, 'Log4Shell');
    expect(out).toContain('Log4Shell');
    expect(out).not.toContain('LFI');
  });

  it('reports when a family is unknown', () => {
    expect(renderCatalog(rules, 'Nonexistent')).toMatch(/No rules in family/);
  });

  it('emits no ANSI or control chars', () => {
    expect(renderCatalog(rules)).not.toMatch(/[\x00-\x08\x0e-\x1f\x7f]/);
  });
});

// The self-documenting commands are the ones an agent most wants to read, and prose is
// the one format it cannot consume structurally.
describe('renderCatalogJson', () => {
  const rules = loadCatalog();

  it('emits every rule with its full field set', () => {
    const out = JSON.parse(renderCatalogJson(rules));
    expect(out.count).toBe(rules.length);
    expect(out.rules).toHaveLength(rules.length);
    const r = out.rules.find((x: { id: string }) => x.id === 'c1-log4shell');
    expect(r).toMatchObject({
      family: 'Log4Shell',
      source: 'CRS:944150',
      severity: 'high',
      target: 'uri',
      sfExploitable: false,
    });
    expect(typeof r.pattern).toBe('string');
    expect(typeof r.note).toBe('string');
  });

  it('filters to a family, case-insensitively, like the human view', () => {
    const out = JSON.parse(renderCatalogJson(rules, 'log4shell'));
    expect(out.rules.every((r: { family: string }) => r.family === 'Log4Shell')).toBe(true);
    expect(out.family).toBe('log4shell');
  });

  it('returns an empty array for an unknown family rather than a prose apology', () => {
    const out = JSON.parse(renderCatalogJson(rules, 'Nonexistent'));
    expect(out.rules).toEqual([]);
    expect(out.count).toBe(0);
  });
});
