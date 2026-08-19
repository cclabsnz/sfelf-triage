import { join } from 'node:path';

/** Where the sf-audit plugin keeps its per-org baseline, relative to the user's home. */
export const EVENT_BASELINE = '.sf/event-baseline';

export type OrgDirResult = { ok: true; dir: string } | { ok: false; error: string };

/**
 * Turn an org id into the directory the sf-audit plugin downloads into.
 *
 * `--org 00D...` exists because that path is the documented happy path, and typing it
 * by hand is the step most likely to be got wrong. The id is interpolated into a
 * filesystem path, so it is validated as a single path segment first: a separator or a
 * parent reference here would let `--org` read anywhere the analyst can, which is not
 * what a convenience flag is allowed to do.
 *
 * The rule is "one safe segment" rather than "a Salesforce id", because the directory
 * is equally often named after an alias.
 */
export function resolveOrgDir(orgId: string, home: string): OrgDirResult {
  if (orgId === '') {
    return { ok: false, error: 'org id is empty' };
  }
  if (/[/\\]/.test(orgId)) {
    return { ok: false, error: 'org id must be a single directory name, with no path separator' };
  }
  if (orgId.includes('\0')) {
    return { ok: false, error: 'org id contains a NUL byte' };
  }
  if (orgId.startsWith('.')) {
    return { ok: false, error: 'org id must not start with "." — that names a hidden sibling, not an org' };
  }
  return { ok: true, dir: join(home, EVENT_BASELINE, orgId) };
}

export interface TargetRequest {
  /** The positional `<dir>` argument, when given. */
  readonly dir?: string;
  /** The `--org` flag, when given. */
  readonly org?: string;
  /** The user's home directory (`os.homedir()`). */
  readonly home: string;
}

/**
 * Decide which directory `analyze` should read, from the positional argument and --org.
 *
 * Supplying both is refused rather than resolved by precedence. Either choice would be
 * defensible and neither is guessable from the outside, so a caller who passed both has
 * a bug and should hear about it before a scan runs against the directory they did not
 * mean.
 */
export function resolveTarget(req: TargetRequest): OrgDirResult {
  if (req.dir !== undefined && req.org !== undefined) {
    return { ok: false, error: 'pass either a directory or --org, not both' };
  }
  if (req.org !== undefined) return resolveOrgDir(req.org, req.home);
  if (req.dir !== undefined) return { ok: true, dir: req.dir };
  return {
    ok: false,
    error: 'no logs to analyze — pass a directory (or a single CSV), or --org <orgId> to read ~/.sf/event-baseline/<orgId>',
  };
}
