# AGENTS.md

Machine-facing contract for `sfelf-triage`. Human rationale lives in [README.md](README.md);
this file is the interface only.

## What it does

Reads already-downloaded Salesforce EventLogFile CSVs from disk and emits a per-IP
verdict. No network access, no Salesforce connection, no writes outside `--out`.

## Invocation

```
sfelf-triage analyze [dir] [--org <orgId>] [--json|--md] [--why] [-o <file>]
                     [--fail-on <verdict>] [--require-re2] [--max-rows <n>]
sfelf-triage catalog [--family <name>] [--json]
sfelf-triage explain [verdict] [--json]
sfelf-triage doctor [--json]
```

`[dir]` is a directory (searched recursively) or a single CSV. Pass a directory **or**
`--org`, never both. `--org <id>` resolves to `~/.sf/event-baseline/<id>` and rejects
anything that is not a single path segment.

Input filenames must be `<EventType>-YYYY-MM-DD.csv`, or `<EventType>/YYYY-MM-DD-<Id>.csv`
in the sf-audit plugin layout. Unmatched CSVs are listed on stderr with a per-file reason.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; with `--fail-on`, nothing reached the threshold |
| 1 | error — bad path, no CSVs, bad argument, unwritable `--out`, unknown `explain` verdict |
| 2 | degraded — `--require-re2` with no RE2, or `doctor` found a degraded install |
| 3 | `--fail-on` threshold met |
| 4 | `--fail-on` not met, but the run was truncated at a resource ceiling — **not** a pass |

Verdict severity ascends `BENIGN_SCANNER` (0) < `SUSPICIOUS` (1) < `LIKELY_ABUSE` (2).
`--fail-on` is inclusive of everything at or above the named verdict.

## Streams

- **stdout** — the report, or the file is written when `-o/--out` is given (stdout then stays empty).
- **stderr** — engine-degradation warnings, truncation notices, gate messages, errors.

Never infer success from stdout alone. Check the exit code, and in `--json` check
`engine` and `truncated` before acting on `verdicts`.

## Output shapes

### `analyze --json`

```ts
{
  engine: 're2' | 'js',
  degradedReason: string | null,   // non-null iff engine === 'js'
  truncated: boolean,              // true => verdicts are a LOWER BOUND
  limitsReached: Record<string, number>,
  stats: { files: number, rows: number },
  verdicts: Array<{
    ip: string,
    verdict: 'BENIGN_SCANNER' | 'SUSPICIOUS' | 'LIKELY_ABUSE',
    reasons: string[],
    totalReqs: number,
    distinctUris: number,          // a FLOOR when distinctUrisTruncated
    distinctUrisTruncated: boolean,
    families: Record<string, number>,
    sfExploitableHits: number,
    allResponsesErrorOrCanned: boolean,
    confidence: string
  }>
}
```

### `catalog --json`

```ts
{ family: string | null, count: number, rules: Array<{
  id, family, source, severity: 'info'|'low'|'medium'|'high',
  target: 'uri'|'query'|'action'|'header', pattern: string,
  sfExploitable: boolean, note: string }> }
```

`sfExploitable: true` is Class 2 (Salesforce-exploitable); `false` is Class 1 (generic
probe, inert on this platform).

### `explain --json`

```ts
{ verdicts: Array<{ verdict, severity: 0|1|2, meaning: string }>,
  decisionOrder: string[], scope: string }
// unknown verdict -> { error: string, knownVerdicts: string[] }, exit 1
```

### `doctor --json`

```ts
{ status: 'ok' | 'degraded',
  node: { version, supportedRange, supported: boolean | null },
  engine: { name: 're2'|'js', degradedReason: string | null, remedy: string | null },
  limits: Record<string, number> }
```

`node.supported` is `null` when the declared range uses syntax the check cannot parse —
that is "unverified", not "unsupported", and does not make `status` degraded.

## Interpreting a result

- `LIKELY_ABUSE` is a **lead**, not proof. EventLogFile carries no response body. Confirm
  in the `forensics-db` DuckDB layer plus the guest user's access rights before asserting
  data was returned.
- `engine: 'js'` means matching was not ReDoS-immune. Findings are still valid; the
  availability guarantee is not. Fix with `pnpm rebuild re2`.
- `truncated: true` means absence of a finding proves nothing. Narrow the input and re-run.

## Reliable one-liners

```bash
sfelf-triage doctor --json | jq -e '.status == "ok"'          # install is trustworthy
sfelf-triage analyze ./logs --json --require-re2 | jq '.verdicts[] | select(.verdict=="LIKELY_ABUSE")'
sfelf-triage analyze ./logs --fail-on LIKELY_ABUSE            # exit 3 on findings, 4 if inconclusive
sfelf-triage catalog --json | jq '[.rules[] | select(.sfExploitable)] | length'
```
