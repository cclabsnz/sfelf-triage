import { createRequire } from 'node:module';
import { MAX_FIELD } from '../sanitizer/ingress.js';

// ESM projects cannot use bare `require()`. This shim restores it for the
// native re2 binding which ships as a CommonJS module.
const require = createRequire(import.meta.url);

type Compiled = { test(s: string): boolean };
type Compiler = (source: string, flags: string) => Compiled;
export type Engine = 're2' | 'js';

/** Result of trying to load the native RE2 binding. */
export interface Re2Load {
  readonly ctor: (new (s: string, f: string) => Compiled) | null;
  /** Why RE2 is unavailable — null when it loaded. */
  readonly reason: string | null;
}

/**
 * The only place a regex runs against untrusted text.
 *
 * Prefers RE2 (linear-time, ReDoS-immune). Falls back to JS `RegExp` when the
 * native binding is unavailable; the fallback relies on the MAX_FIELD input cap
 * to bound backtracking. Patterns come only from our own catalog, never user input.
 *
 * The fallback is a real reduction in the guarantee this tool advertises, so it is
 * never silent: `engine` and `degradedReason` are surfaced by the CLI on stderr and
 * in `--json` output, and `sfelf-triage analyze --require-re2` turns it into a
 * hard failure for pipelines that must not run degraded.
 */
export class SafeMatcher {
  private readonly compile: Compiler;
  readonly engine: Engine;
  /** Non-null exactly when `engine === 'js'`: why RE2 could not be used. */
  readonly degradedReason: string | null;
  private readonly cache = new Map<string, Compiled>();

  constructor(load: () => Re2Load = loadRe2) {
    const { ctor, reason } = load();
    if (ctor) {
      this.engine = 're2';
      this.degradedReason = null;
      this.compile = (source, flags) => new ctor(source, flags);
    } else {
      this.engine = 'js';
      this.degradedReason = reason ?? 'RE2 unavailable for an unknown reason';
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

/**
 * Load the native RE2 binding, capturing *why* it failed rather than discarding it.
 * The common failure is an ABI mismatch after a Node upgrade (`ERR_DLOPEN_FAILED`,
 * "compiled against a different Node.js version") — a silent fallback there would
 * quietly drop the ReDoS guarantee on a working-looking install.
 */
export function loadRe2(): Re2Load {
  try {
    // Dynamic require so a missing native binding degrades instead of crashing.
    const mod = require('re2') as new (s: string, f: string) => Compiled;
    return { ctor: mod, reason: null };
  } catch (err) {
    return { ctor: null, reason: describeLoadFailure(err) };
  }
}

/** Turn a binding-load failure into an operator-actionable sentence. Exported for tests. */
export function describeLoadFailure(err: unknown): string {
  const e = err as { code?: string; message?: string };
  const code = typeof e?.code === 'string' ? e.code : null;
  const message = typeof e?.message === 'string' ? e.message.split('\n')[0] : String(err);

  if (code === 'ERR_DLOPEN_FAILED' && /NODE_MODULE_VERSION/.test(String(e.message))) {
    return (
      'the native RE2 binding was built for a different Node.js ABI than the one running ' +
      `(${process.version}); rebuild it with "pnpm rebuild re2"`
    );
  }
  if (code === 'MODULE_NOT_FOUND') {
    return 'the re2 package is not installed; run "pnpm install"';
  }
  return code ? `${code}: ${message}` : message;
}
