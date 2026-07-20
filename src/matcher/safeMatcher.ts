import { createRequire } from 'node:module';
import { MAX_FIELD } from '../sanitizer/ingress.js';

// ESM projects cannot use bare `require()`. This shim restores it for the
// native re2 binding which ships as a CommonJS module.
const require = createRequire(import.meta.url);

type Compiler = (source: string, flags: string) => { test(s: string): boolean };

/**
 * The only place a regex runs against untrusted text.
 * Prefers RE2 (linear-time, ReDoS-immune). Falls back to JS RegExp when the
 * native binding is unavailable; the fallback relies on the MAX_FIELD input cap
 * to bound backtracking. Patterns come only from our own catalog, never user input.
 */
export class SafeMatcher {
  private readonly compile: Compiler;
  readonly engine: 're2' | 'js';
  private readonly cache = new Map<string, { test(s: string): boolean }>();

  constructor() {
    const re2 = loadRe2();
    if (re2) {
      this.engine = 're2';
      this.compile = (source, flags) => new re2(source, flags);
    } else {
      this.engine = 'js';
      this.compile = (source, flags) => new RegExp(source, flags);
    }
  }

  test(pattern: string, input: string): boolean {
    const bounded = input.length > MAX_FIELD ? input.slice(0, MAX_FIELD) : input;
    let re = this.cache.get(pattern);
    if (!re) {
      re = this.compile(pattern, 'i');
      this.cache.set(pattern, re);
    }
    return re.test(bounded);
  }
}

function loadRe2(): (new (s: string, f: string) => { test(x: string): boolean }) | null {
  try {
    // Dynamic require so a missing native binding degrades instead of crashing.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('re2');
    return mod as never;
  } catch {
    return null;
  }
}
