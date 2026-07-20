import { readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export interface LogFile {
  path: string;
  eventType: string;
  date: string;
}

const NAME = /^([A-Za-z]+)-(\d{4}-\d{2}-\d{2})\.csv$/;

export async function discover(dir: string): Promise<LogFile[]> {
  const root = resolve(dir);
  const entries = await readdir(root, { withFileTypes: true });
  const files: LogFile[] = [];
  for (const e of entries) {
    if (!e.isFile()) continue;
    const m = NAME.exec(e.name);
    if (!m) continue;
    const path = join(root, e.name);
    if (!path.startsWith(root)) continue; // confine reads to the given dir
    files.push({ path, eventType: m[1], date: m[2] });
  }
  return files.sort((a, b) => a.path.localeCompare(b.path));
}
