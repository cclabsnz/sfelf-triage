import { describe, it, expect } from 'vitest';
import { egress, csvCell } from './egress.js';

describe('Sanitizer.egress', () => {
  it('strips ANSI escape sequences', () => {
    expect(egress('\x1b[31mred\x1b[0m')).toBe('red');
  });

  it('strips CR/LF and other control chars so a payload cannot spoof the terminal', () => {
    expect(egress('/sfsites/ HTTP/1.1\r\nWas-Header: x')).toBe('/sfsites/ HTTP/1.1Was-Header: x');
  });

  it('prefix-guards CSV cells that could execute as formulas', () => {
    expect(csvCell('=cmd|calc')).toBe("'=cmd|calc");
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('safe')).toBe('safe');
  });
});
