import { describe, it, expect } from 'vitest';
import { renderCatalog } from './catalogView.js';
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
