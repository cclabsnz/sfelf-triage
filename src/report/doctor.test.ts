import { describe, it, expect } from 'vitest';
import { DEFAULT_LIMITS } from '../limits.js';
import { renderDoctor, renderDoctorJson, doctorStatus, satisfiesRange } from './doctor.js';
import type { DoctorInput } from './doctor.js';

const RANGE = '^22.22.2 || ^24.15.0 || >=26.0.0';

function inputOf(over: Partial<DoctorInput> = {}): DoctorInput {
  return {
    nodeVersion: 'v22.22.2',
    supportedRange: RANGE,
    engine: 're2',
    degradedReason: null,
    limits: DEFAULT_LIMITS,
    ...over,
  };
}

describe('satisfiesRange', () => {
  it('accepts a caret match at the floor', () => {
    expect(satisfiesRange('v22.22.2', RANGE)).toBe(true);
  });

  it('accepts a caret match above the floor', () => {
    expect(satisfiesRange('v22.30.0', RANGE)).toBe(true);
  });

  it('rejects a version below the floor of its own major', () => {
    expect(satisfiesRange('v22.20.0', RANGE)).toBe(false);
  });

  it('rejects a major the range does not list', () => {
    expect(satisfiesRange('v20.11.0', RANGE)).toBe(false);
    expect(satisfiesRange('v23.0.0', RANGE)).toBe(false);
  });

  it('honours a >= clause for later majors', () => {
    expect(satisfiesRange('v27.1.0', RANGE)).toBe(true);
  });

  // A wrong "unsupported" is worse than an honest "cannot tell": it would send an
  // analyst reinstalling Node to fix a problem that is not there.
  it('returns null rather than guessing on a range form it cannot parse', () => {
    expect(satisfiesRange('v22.22.2', '22.x || ~24')).toBe(null);
  });
});

describe('doctorStatus', () => {
  it('is ok on RE2 and a supported Node', () => {
    expect(doctorStatus(inputOf())).toBe('ok');
  });

  it('is degraded when the JS fallback is in use', () => {
    expect(doctorStatus(inputOf({ engine: 'js', degradedReason: 'ABI mismatch' }))).toBe('degraded');
  });

  it('is degraded on an unsupported Node even when RE2 loaded', () => {
    expect(doctorStatus(inputOf({ nodeVersion: 'v20.11.0' }))).toBe('degraded');
  });

  it('stays ok when the Node range could not be verified', () => {
    expect(doctorStatus(inputOf({ supportedRange: '22.x' }))).toBe('ok');
  });
});

describe('renderDoctor', () => {
  it('reports the running Node, the range, and the engine', () => {
    const out = renderDoctor(inputOf());
    expect(out).toContain('v22.22.2');
    expect(out).toContain(RANGE);
    expect(out).toContain('re2');
  });

  it('prints the fix for a degraded engine, not just the symptom', () => {
    const out = renderDoctor(inputOf({ engine: 'js', degradedReason: 'ABI mismatch' }));
    expect(out).toContain('ABI mismatch');
    expect(out).toContain('pnpm rebuild re2');
  });

  it('lists the effective resource ceilings', () => {
    expect(renderDoctor(inputOf())).toContain('maxRows');
  });

  it('emits no control characters', () => {
    const nasty = inputOf({ engine: 'js', degradedReason: `bad${String.fromCharCode(27)}[31m` });
    expect(renderDoctor(nasty)).not.toContain(String.fromCharCode(27));
  });
});

describe('renderDoctorJson', () => {
  it('carries status, node, engine and limits', () => {
    const out = JSON.parse(renderDoctorJson(inputOf()));
    expect(out.status).toBe('ok');
    expect(out.node.version).toBe('v22.22.2');
    expect(out.node.supported).toBe(true);
    expect(out.engine.name).toBe('re2');
    expect(out.limits.maxRows).toBe(DEFAULT_LIMITS.maxRows);
  });

  it('carries the degraded reason and its remedy', () => {
    const out = JSON.parse(renderDoctorJson(inputOf({ engine: 'js', degradedReason: 'ABI mismatch' })));
    expect(out.status).toBe('degraded');
    expect(out.engine.degradedReason).toBe('ABI mismatch');
    expect(out.engine.remedy).toContain('pnpm rebuild re2');
  });
});
