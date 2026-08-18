import { describe, it, expect } from 'vitest';
import type { AnalysisReport } from './core/analyze.js';
import { evaluateGate, GATE_EXIT, isVerdict } from './gate.js';
import { LimitReport } from './limits.js';
import { severityOf, VERDICTS, type IpVerdict, type Verdict } from './types.js';

function verdictOf(ip: string, verdict: Verdict): IpVerdict {
  return {
    ip,
    verdict,
    reasons: [],
    totalReqs: 1,
    distinctUris: 1,
    distinctUrisTruncated: false,
    families: {},
    sfExploitableHits: verdict === 'LIKELY_ABUSE' ? 1 : 0,
    allResponsesErrorOrCanned: verdict === 'BENIGN_SCANNER',
    confidence: 'test',
  };
}

function reportOf(verdicts: IpVerdict[], limits = new LimitReport()): AnalysisReport {
  return {
    verdicts,
    engine: 're2',
    degradedReason: null,
    limits,
    stats: { files: 1, rows: verdicts.length },
  };
}

describe('verdict severity ordering', () => {
  // --fail-on derives its threshold ranking from VERDICTS order, so a reorder would
  // silently change which runs fail a pipeline gate.
  it('ranks verdicts least to most severe', () => {
    expect(VERDICTS).toEqual(['BENIGN_SCANNER', 'SUSPICIOUS', 'LIKELY_ABUSE']);
    expect(severityOf('BENIGN_SCANNER')).toBeLessThan(severityOf('SUSPICIOUS'));
    expect(severityOf('SUSPICIOUS')).toBeLessThan(severityOf('LIKELY_ABUSE'));
  });

  it('accepts exactly the known verdicts', () => {
    for (const v of VERDICTS) expect(isVerdict(v)).toBe(true);
    expect(isVerdict('CRITICAL')).toBe(false);
    expect(isVerdict('likely_abuse')).toBe(false); // the CLI upper-cases before checking
  });
});

describe('evaluateGate', () => {
  it('passes when nothing reaches the threshold', () => {
    const gate = evaluateGate(reportOf([verdictOf('203.0.113.1', 'SUSPICIOUS')]), 'LIKELY_ABUSE');
    expect(gate.exitCode).toBe(0);
    expect(gate.message).toBeNull();
    expect(gate.triggering).toHaveLength(0);
  });

  it('passes on an empty result set', () => {
    expect(evaluateGate(reportOf([]), 'BENIGN_SCANNER').exitCode).toBe(0);
  });

  it('fails when an IP meets the threshold exactly', () => {
    const gate = evaluateGate(reportOf([verdictOf('203.0.113.1', 'SUSPICIOUS')]), 'SUSPICIOUS');
    expect(gate.exitCode).toBe(GATE_EXIT.FINDINGS);
    expect(gate.triggering.map((v) => v.ip)).toEqual(['203.0.113.1']);
  });

  it('fails when an IP exceeds the threshold', () => {
    const gate = evaluateGate(reportOf([verdictOf('203.0.113.1', 'LIKELY_ABUSE')]), 'SUSPICIOUS');
    expect(gate.exitCode).toBe(GATE_EXIT.FINDINGS);
  });

  it('reports the most severe verdict first and names it in the message', () => {
    const gate = evaluateGate(
      reportOf([
        verdictOf('203.0.113.1', 'SUSPICIOUS'),
        verdictOf('203.0.113.2', 'LIKELY_ABUSE'),
        verdictOf('203.0.113.3', 'SUSPICIOUS'),
      ]),
      'SUSPICIOUS',
    );
    expect(gate.triggering).toHaveLength(3);
    expect(gate.triggering[0].verdict).toBe('LIKELY_ABUSE');
    expect(gate.message).toContain('most severe: LIKELY_ABUSE');
    expect(gate.message).toContain('3 IP(s)');
  });

  it('catches everything flagged at the lowest threshold', () => {
    const gate = evaluateGate(reportOf([verdictOf('203.0.113.1', 'BENIGN_SCANNER')]), 'BENIGN_SCANNER');
    expect(gate.exitCode).toBe(GATE_EXIT.FINDINGS);
  });

  // A gate has three answers, not two. Collapsing "could not tell" into "clean" is how a
  // truncated analysis becomes a false all-clear in a pipeline that only checks for zero.
  describe('when the run was truncated', () => {
    const truncated = () => {
      const l = new LimitReport();
      l.reached('maxRows');
      return l;
    };

    it('reports inconclusive rather than passing when nothing was found', () => {
      const gate = evaluateGate(reportOf([], truncated()), 'LIKELY_ABUSE');
      expect(gate.exitCode).toBe(GATE_EXIT.INCONCLUSIVE);
      expect(gate.message).toMatch(/not a clean result/i);
    });

    it('still reports findings when something was found — the question is answered', () => {
      const gate = evaluateGate(
        reportOf([verdictOf('203.0.113.1', 'LIKELY_ABUSE')], truncated()),
        'LIKELY_ABUSE',
      );
      expect(gate.exitCode).toBe(GATE_EXIT.FINDINGS);
    });

    it('uses a distinct code from findings, so a pipeline can tell them apart', () => {
      expect(GATE_EXIT.INCONCLUSIVE).not.toBe(GATE_EXIT.FINDINGS);
    });
  });

  // The JS fallback finds the same matches as RE2; what it loses is the linear-time
  // guarantee. --require-re2 is the control for that, so the findings gate stays silent.
  it('does not treat a degraded regex engine as inconclusive', () => {
    const degraded: AnalysisReport = {
      ...reportOf([verdictOf('203.0.113.1', 'BENIGN_SCANNER')]),
      engine: 'js',
      degradedReason: 'ABI mismatch',
    };
    expect(evaluateGate(degraded, 'LIKELY_ABUSE').exitCode).toBe(0);
  });
});
