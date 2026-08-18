import { readdir, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { DEFAULT_LIMITS, LimitReport, type Limits } from '../limits.js';

export interface LogFile {
  path: string;
  eventType: string;
  date: string;
}

// Flat convention (forensics-db / manual): `Sites-2024-01-15.csv`.
const FLAT = /^([A-Za-z]+)-(\d{4}-\d{2}-\d{2})\.csv$/;
// sf-audit plugin convention: `<EventType>/2024-01-15-<Id>.csv` (EventType is the parent dir).
const NESTED = /^(\d{4}-\d{2}-\d{2})-.+\.csv$/;
const EVENT_TYPE_DIR = /^[A-Za-z]+$/;

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
 * Discover EventLogFile CSVs under `dir`, recursively. Recognizes both the flat
 * `<EventType>-YYYY-MM-DD.csv` naming and the sf-audit plugin's nested
 * `<EventType>/YYYY-MM-DD-<Id>.csv` layout.
 *
 * Reads are confined to the *resolved* `dir`. Symbolic links are not followed, by
 * policy: a log directory is attacker-adjacent input (it is often unpacked from an
 * archive supplied by whoever is being investigated), and following links would let a
 * planted entry walk the analyst's filesystem or loop the traversal forever.
 *
 * Traversal is bounded by `limits.maxDepth` and `limits.maxFiles`; anything dropped is
 * recorded in `report` rather than discarded quietly.
 */
export async function discover(
  dir: string,
  limits: Limits = DEFAULT_LIMITS,
  report: LimitReport = new LimitReport(),
): Promise<LogFile[]> {
  // Resolve symlinks in the root itself so an intentionally symlinked log directory
  // still works, while links *inside* the tree remain unfollowed.
  const root = await realpath(resolve(dir)).catch(() => resolve(dir));
  const files: LogFile[] = [];
  await walk(root, root, 0, files, limits, report);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

async function walk(
  current: string,
  root: string,
  depth: number,
  out: LogFile[],
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
    if (out.length >= limits.maxFiles) {
      report.reached('maxFiles');
      return;
    }
    const full = join(current, e.name);
    if (!isWithin(root, full)) continue; // confine reads to the given dir

    // Dirent classification is lstat-based, so a symlink is neither isDirectory()
    // nor isFile() and is skipped here. Stated explicitly because the behaviour is
    // load-bearing, not incidental — see the policy note on discover().
    if (e.isSymbolicLink()) continue;

    if (e.isDirectory()) {
      if (e.name === '_manifests') continue; // plugin's per-run manifests, not logs
      await walk(full, root, depth + 1, out, limits, report);
      continue;
    }
    if (!e.isFile()) continue;

    const flat = FLAT.exec(e.name);
    if (flat) {
      out.push({ path: full, eventType: flat[1], date: flat[2] });
      continue;
    }
    const nested = NESTED.exec(e.name);
    if (nested) {
      const parent = basename(dirname(full));
      if (EVENT_TYPE_DIR.test(parent)) {
        out.push({ path: full, eventType: parent, date: nested[1] });
      }
    }
  }
}
