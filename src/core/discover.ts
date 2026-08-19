import { readdir, realpath, stat } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { DEFAULT_LIMITS, LimitReport, type Limits } from '../limits.js';

export interface LogFile {
  path: string;
  eventType: string;
  date: string;
}

/** A `.csv` that was found but not recognized, with the reason it was skipped. */
export interface RejectedFile {
  readonly name: string;
  readonly path: string;
  readonly reason: string;
}

export interface Discovery {
  readonly files: LogFile[];
  /** A bounded sample of rejected CSVs — see MAX_REJECT_SAMPLES. */
  readonly rejected: RejectedFile[];
  /** How many CSVs were rejected in total; `rejected.length` is a sample of this. */
  readonly rejectedTotal: number;
}

/**
 * Rejected filenames are attacker-shaped input accumulated for a human error message,
 * so the list is a bounded sample rather than a full record. Three or four examples
 * are what makes a naming mismatch obvious; ten thousand is a memory profile.
 */
export const MAX_REJECT_SAMPLES = 20;

// Flat convention (forensics-db / manual): `Sites-2024-01-15.csv`.
const FLAT = /^([A-Za-z]+)-(\d{4}-\d{2}-\d{2})\.csv$/;
// sf-audit plugin convention: `<EventType>/2024-01-15-<Id>.csv` (EventType is the parent dir).
const NESTED = /^(\d{4}-\d{2}-\d{2})-.+\.csv$/;
const EVENT_TYPE_DIR = /^[A-Za-z]+$/;
const ANY_DATE = /\d{4}-\d{2}-\d{2}/;
const DUPLICATE_SUFFIX = /\s\(\d+\)\.csv$/i;

/**
 * True when `candidate` is `root` itself or genuinely beneath it.
 *
 * A `startsWith` prefix test is not sufficient: it accepts `/logs-evil` for a root of
 * `/logs`, because the string boundary is not a path boundary. `relative()` compares
 * path segments, so an escape shows up as a leading `..` and an unrelated sibling as
 * an absolute result.
 */
function isWithin(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Classify one CSV filename against both supported layouts, or return null.
 * `parent` is the containing directory's basename, which carries the event type in
 * the nested layout.
 */
function classify(full: string, name: string, parent: string): LogFile | null {
  const flat = FLAT.exec(name);
  if (flat) return { path: full, eventType: flat[1], date: flat[2] };

  const nested = NESTED.exec(name);
  if (nested && EVENT_TYPE_DIR.test(parent)) {
    return { path: full, eventType: parent, date: nested[1] };
  }
  return null;
}

/**
 * Explain why a `.csv` was not recognized, in terms of the thing to change.
 *
 * A rejection the analyst cannot act on is the same as no message at all: the failure
 * mode this replaces was "no EventLogFile CSVs found" printed over a directory full of
 * CSVs that were one character away from matching.
 */
export function rejectReason(name: string, parent: string): string {
  if (DUPLICATE_SUFFIX.test(name)) {
    return 'has a duplicate-download suffix like " (1)" — remove it';
  }
  if (FLAT.test(name.replace('_', '-'))) {
    return 'uses an underscore between event type and date — expected a hyphen';
  }
  if (!ANY_DATE.test(name)) {
    return 'carries no YYYY-MM-DD date — expected <EventType>-YYYY-MM-DD.csv';
  }
  if (NESTED.test(name) && !EVENT_TYPE_DIR.test(parent)) {
    return `is date-prefixed, but its parent directory "${parent}" is not an EventType name`;
  }
  return 'does not match <EventType>-YYYY-MM-DD.csv or <EventType>/YYYY-MM-DD-<Id>.csv';
}

/**
 * Discover EventLogFile CSVs under `target`, recursively, alongside the CSVs that were
 * skipped and why. `target` may be a directory or a single CSV file.
 *
 * Reads are confined to the *resolved* `target`. Symbolic links are not followed, by
 * policy: a log directory is attacker-adjacent input (it is often unpacked from an
 * archive supplied by whoever is being investigated), and following links would let a
 * planted entry walk the analyst's filesystem or loop the traversal forever.
 *
 * Traversal is bounded by `limits.maxDepth` and `limits.maxFiles`; anything dropped is
 * recorded in `report` rather than discarded quietly.
 */
export async function discoverDetailed(
  target: string,
  limits: Limits = DEFAULT_LIMITS,
  report: LimitReport = new LimitReport(),
): Promise<Discovery> {
  // Resolve symlinks in the target itself so an intentionally symlinked log directory
  // or file still works, while links *inside* the tree remain unfollowed.
  const root = await realpath(resolve(target)).catch(() => resolve(target));
  const acc: Accumulator = { files: [], rejected: [], rejectedTotal: 0 };

  const info = await stat(root).catch(() => null);
  if (info?.isFile()) {
    const name = basename(root);
    if (name.toLowerCase().endsWith('.csv')) {
      const parent = basename(dirname(root));
      const hit = classify(root, name, parent);
      if (hit) acc.files.push(hit);
      else pushReject(acc, root, name, parent);
    }
  } else {
    await walk(root, root, 0, acc, limits, report);
  }

  acc.files.sort((a, b) => a.path.localeCompare(b.path));
  return acc;
}

/** Discover EventLogFile CSVs under `target`. See {@link discoverDetailed}. */
export async function discover(
  target: string,
  limits: Limits = DEFAULT_LIMITS,
  report: LimitReport = new LimitReport(),
): Promise<LogFile[]> {
  return (await discoverDetailed(target, limits, report)).files;
}

interface Accumulator {
  files: LogFile[];
  rejected: RejectedFile[];
  rejectedTotal: number;
}

function pushReject(acc: Accumulator, full: string, name: string, parent: string): void {
  acc.rejectedTotal += 1;
  if (acc.rejected.length < MAX_REJECT_SAMPLES) {
    acc.rejected.push({ name, path: full, reason: rejectReason(name, parent) });
  }
}

async function walk(
  current: string,
  root: string,
  depth: number,
  acc: Accumulator,
  limits: Limits,
  report: LimitReport,
): Promise<void> {
  if (depth > limits.maxDepth) {
    report.reached('maxDepth');
    return;
  }
  let entries;
  try {
    entries = await readdir(current, { withFileTypes: true });
  } catch {
    return; // unreadable dir — skip rather than throw
  }
  for (const e of entries) {
    if (acc.files.length >= limits.maxFiles) {
      report.reached('maxFiles');
      return;
    }
    const full = join(current, e.name);
    if (!isWithin(root, full)) continue; // confine reads to the given dir

    // Dirent classification is lstat-based, so a symlink is neither isDirectory()
    // nor isFile() and is skipped here. Stated explicitly because the behaviour is
    // load-bearing, not incidental — see the policy note on discoverDetailed().
    if (e.isSymbolicLink()) continue;

    if (e.isDirectory()) {
      if (e.name === '_manifests') continue; // plugin's per-run manifests, not logs
      await walk(full, root, depth + 1, acc, limits, report);
      continue;
    }
    if (!e.isFile()) continue;

    const parent = basename(current);
    const hit = classify(full, e.name, parent);
    if (hit) {
      acc.files.push(hit);
      continue;
    }
    // Only CSVs are reported as rejects: a log directory legitimately contains
    // manifests, notes and archives, and naming those as problems is noise.
    if (e.name.toLowerCase().endsWith('.csv')) pushReject(acc, full, e.name, parent);
  }
}
