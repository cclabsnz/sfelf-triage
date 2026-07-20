import { readdir } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

export interface LogFile {
  path: string;
  eventType: string;
  date: string;
}

// Flat convention (forensics-db / manual): `Sites-2026-07-15.csv`.
const FLAT = /^([A-Za-z]+)-(\d{4}-\d{2}-\d{2})\.csv$/;
// sf-audit plugin convention: `<EventType>/2026-07-15-<Id>.csv` (EventType is the parent dir).
const NESTED = /^(\d{4}-\d{2}-\d{2})-.+\.csv$/;
const EVENT_TYPE_DIR = /^[A-Za-z]+$/;

/**
 * Discover EventLogFile CSVs under `dir`, recursively. Recognizes both the flat
 * `<EventType>-YYYY-MM-DD.csv` naming and the sf-audit plugin's nested
 * `<EventType>/YYYY-MM-DD-<Id>.csv` layout. Reads are confined to `dir`.
 */
export async function discover(dir: string): Promise<LogFile[]> {
  const root = resolve(dir);
  const files: LogFile[] = [];
  await walk(root, root, files);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

async function walk(current: string, root: string, out: LogFile[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(current, { withFileTypes: true });
  } catch {
    return; // unreadable dir — skip rather than throw
  }
  for (const e of entries) {
    const full = join(current, e.name);
    if (!full.startsWith(root)) continue; // confine reads to the given dir
    if (e.isDirectory()) {
      if (e.name === '_manifests') continue; // plugin's per-run manifests, not logs
      await walk(full, root, out);
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
