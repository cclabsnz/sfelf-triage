# sfelf-triage

Forensic triage for already-downloaded Salesforce EventLogFile CSVs. Point it at a
directory of logs; it matches guest/community traffic against a catalog of exploit and
abuse patterns and emits a per-IP verdict.

Built to answer one question fast: **when a guest/community IP is flagged (e.g. "Log4j
exploitation"), is it a vulnerability scanner or a real threat?** It runs with **zero
network egress**, so it is safe on sensitive (e.g. PII-bearing) logs and air-gapped hosts, and
needs no Salesforce connection — collection happens separately, this tool only reads the
files.

## Verdicts

| Verdict | Meaning |
|---|---|
| `BENIGN_SCANNER` | Class-1 probes only (Log4Shell/LFI/rwservlet — inert on Salesforce) and every matched response was an error or a canned page. An automated scan, not a breach. |
| `SUSPICIOUS` | Probe matches whose responses were not all error/canned — a real content-sized response came back. Worth a look. |
| `LIKELY_ABUSE` | A Salesforce-exploitable (Class-2) match — e.g. a guest GraphQL bulk read — or a read-then-download correlation. Behaviour that can touch real data. |

Run `sfelf-triage explain` for the full decision logic, or `explain --json` for the same
thing as data.

## Install

Requires Node `^22.22.2 || ^24.15.0 || >=26.0.0` — the range `re2` supports. Node 20 is
not supported: it reached end of life on 2026-04-30, and the `re2` versions that carry
no open advisories do not run on it.

```bash
npm install -g sfelf-triage

sfelf-triage doctor          # confirm the install is healthy before trusting a run
```

Or straight from the repo, to run an unreleased revision:

```bash
npm install -g github:cclabsnz/sfelf-triage
```

Or from a clone, for development:

```bash
pnpm install                 # builds dist/ via the prepare script
sfelf-triage --help          # after `pnpm link --global`, or use `node dist/cli.js`
```

Examples below use `sfelf-triage`; substitute `node dist/cli.js` in a clone you have not
linked.

### Your logs must be named correctly

This is the single most common reason a first run finds nothing. Two layouts are
recognized, and `analyze` reads either recursively:

| Layout | Example | Produced by |
|---|---|---|
| Flat | `Sites-2024-01-15.csv` | `forensics-db`, manual downloads |
| Nested | `<orgId>/Sites/2024-01-15-0AT....csv` | the [sf-audit plugin](https://github.com/cclabsnz/sf-audit-plugin) (its `_manifests/` dir is ignored) |

If nothing matches, the tool lists what it saw and what is wrong with each name — you do
not have to guess:

```
$ sfelf-triage analyze ./logs
sfelf-triage: no EventLogFile CSVs found in "./logs".
  Saw 3 .csv file(s), none of them recognized:
    EventLogFile.csv          -> carries no YYYY-MM-DD date — expected <EventType>-YYYY-MM-DD.csv
    Sites-2026-08-14 (1).csv  -> has a duplicate-download suffix like " (1)" — remove it
    Sites_2026-08-14.csv      -> uses an underscore between event type and date — expected a hyphen
  Expected <EventType>-YYYY-MM-DD.csv, or <EventType>/YYYY-MM-DD-<Id>.csv.
```

## Quick start

```bash
# 1. Get the logs (any download method works; the tool only needs the CSVs)
sf audit events pull -o <org> --since 7 --output ./logs

# 2. Triage them
sfelf-triage analyze ./logs

# 3. Or skip the path entirely if you used the sf-audit plugin
sfelf-triage analyze --org 00D...        # reads ~/.sf/event-baseline/00D...
```

## Commands

```bash
# Triage a directory, or a single CSV
sfelf-triage analyze ./logs                    # table (default)
sfelf-triage analyze ./logs --why              # table + why each verdict was reached
sfelf-triage analyze ./logs --json             # JSON for pipelines
sfelf-triage analyze ./logs --md --out r.md    # markdown, written to a file
sfelf-triage analyze Sites-2024-01-15.csv      # one file is a valid target
sfelf-triage analyze --org 00D...              # ~/.sf/event-baseline/<orgId>

# Learn what the tool does — it documents itself
sfelf-triage catalog                           # every detection rule it checks
sfelf-triage catalog --family Log4Shell
sfelf-triage catalog --json                    # the same rules as data
sfelf-triage explain                           # what every verdict means
sfelf-triage explain LIKELY_ABUSE
sfelf-triage explain --json

# Check the installation
sfelf-triage doctor                            # Node, regex engine, resource ceilings
sfelf-triage doctor --json

sfelf-triage --help                            # top-level help
sfelf-triage analyze --help                    # per-command help + examples
sfelf-triage --version
```

`--org` takes the directory name under `~/.sf/event-baseline`, and refuses anything that
is not a single path segment — it is a convenience flag, not a way to read arbitrary
paths. Pass a directory *or* `--org`, never both.

## Output

### Table (default)

```
$ sfelf-triage analyze ./logs
┌───────────────┬──────────────┬──────┬───────────────┬────────┬───────────────────────────┐
│ IP            │ Verdict      │ Reqs │ Distinct URIs │ sfHits │ Families                  │
├───────────────┼──────────────┼──────┼───────────────┼────────┼───────────────────────────┤
│ 198.51.100.23 │ LIKELY_ABUSE │ 1    │ 1             │ 1      │ Guest-GraphQL-bulk-read:1 │
└───────────────┴──────────────┴──────┴───────────────┴────────┴───────────────────────────┘
```

`--why` adds the reasoning behind each verdict:

```
$ sfelf-triage analyze ./logs --why
│ 198.51.100.23 │ LIKELY_ABUSE │ 1 │ 1 │ 1 │ Guest-GraphQL-bulk-read:1 │ 1 Salesforce-exploitable match(es) │
```

A `Distinct URIs` value shown as `>=1000` is a floor, not a count: the per-IP ceiling was
reached. `--md` produces the same table as GFM for an incident record, with a
`Confidence` column in place of `Families`.

### JSON (`--json`)

```json
{
  "engine": "re2",
  "degradedReason": null,
  "truncated": false,
  "limitsReached": {},
  "stats": { "files": 1, "rows": 1 },
  "verdicts": [
    {
      "ip": "198.51.100.23",
      "verdict": "LIKELY_ABUSE",
      "reasons": ["1 Salesforce-exploitable match(es)"],
      "totalReqs": 1,
      "distinctUris": 1,
      "distinctUrisTruncated": false,
      "families": { "Guest-GraphQL-bulk-read": 1 },
      "sfExploitableHits": 1,
      "allResponsesErrorOrCanned": false,
      "confidence": "Behavioural/exploitable signal present; confirm record return via forensics-db + guest access rights."
    }
  ]
}
```

The verdicts sit under a `verdicts` key rather than at the top level so a consumer can
see, in the same document, which engine produced them and whether the run was complete.

**Top level**

| Field | Type | Meaning |
|---|---|---|
| `engine` | `"re2" \| "js"` | Regex engine that produced every match in this run. |
| `degradedReason` | `string \| null` | Non-null exactly when `engine` is `"js"`. |
| `truncated` | `boolean` | True when any resource ceiling was reached. Verdicts are then a lower bound. |
| `limitsReached` | `{ [limit: string]: number }` | Which ceilings bit, and how many times. Empty when complete. |
| `stats.files` | `number` | CSVs analyzed. |
| `stats.rows` | `number` | Rows ingested. |
| `verdicts` | `IpVerdict[]` | One entry per flagged IP; empty when nothing matched. |

**`IpVerdict`**

| Field | Type | Meaning |
|---|---|---|
| `ip` | `string` | Client IP. |
| `verdict` | `"BENIGN_SCANNER" \| "SUSPICIOUS" \| "LIKELY_ABUSE"` | Ordered ascending by severity. |
| `reasons` | `string[]` | Why the scorer reached this verdict. |
| `totalReqs` | `number` | Matched requests from this IP. |
| `distinctUris` | `number` | Distinct URIs seen — a **floor** when `distinctUrisTruncated` is true. |
| `distinctUrisTruncated` | `boolean` | True when the per-IP URI ceiling was reached. |
| `families` | `{ [family: string]: number }` | Rule family → hit count. |
| `sfExploitableHits` | `number` | Class-2 (Salesforce-exploitable) matches. |
| `allResponsesErrorOrCanned` | `boolean` | True when no matched response looked like real content. |
| `confidence` | `string` | Honesty note on what this run can and cannot prove. |

## Gating a pipeline

`analyze` reports rather than judges by default — it always exits `0` when it ran. Pass
`--fail-on <verdict>` to turn a result into a build failure:

```bash
sfelf-triage analyze ./logs --fail-on LIKELY_ABUSE            # fail on data-touching behaviour
sfelf-triage analyze ./logs --fail-on SUSPICIOUS --require-re2 # stricter, and refuse to run degraded
sfelf-triage analyze ./logs --max-rows 50000                   # fast sample pass (reports PARTIAL)
```

The threshold is inclusive and ordered `BENIGN_SCANNER < SUSPICIOUS < LIKELY_ABUSE`, so
`--fail-on SUSPICIOUS` also fails on `LIKELY_ABUSE`.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | analysis ran; with `--fail-on`, nothing reached the threshold |
| `1` | error — missing/unreadable dir, no CSVs, bad argument, unwritable `--out` |
| `2` | `--require-re2` given but the native RE2 engine is unavailable (also `doctor`'s degraded code) |
| `3` | `--fail-on` threshold met — one or more IPs reached that verdict |
| `4` | `--fail-on` threshold not met, but the run was truncated at a resource ceiling |

`4` is deliberately distinct from `0`. A gate has three answers, not two: something was
found, nothing was found, and the run was not complete enough to say. Treating the third
as a pass is how a truncated analysis becomes a false all-clear.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `no EventLogFile CSVs found` | Filenames do not match either layout. | Read the per-file reasons the error prints, then rename. See [naming](#your-logs-must-be-named-correctly). |
| `WARNING — running on the JS regex fallback` | The native RE2 binding did not load, usually an ABI mismatch after a Node upgrade. | `pnpm rebuild re2`, then `sfelf-triage doctor` to confirm. |
| `engines` error on install | Running Node 20 or another unsupported version. | Install a Node in the supported range; `.nvmrc` pins the floor. |
| `PARTIAL ANALYSIS` banner | A resource ceiling in `src/limits.ts` was reached. | Narrow the input (fewer days, one event type) and re-run. Treat verdicts as a lower bound. |
| `pass either a directory or --org, not both` | Both input forms were given. | Pick one. |

`sfelf-triage doctor` diagnoses the first three in one command and prints the fix.

## How it works

A streaming pipeline wrapped by a single trust boundary:

```
discover → ingest → match → correlate → score → report
                    (all hostile-input handling in ingress / SafeMatcher / egress)
```

The tool ingests hostile input by definition, so all decoding, regex execution, and
output live in three single-responsibility units; the core is pure logic over a branded
`SafeEvent`. Analysis is a single pass that retains no events, so memory scales with the
number of distinct client IPs rather than the size of the logs. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY.md](docs/SECURITY.md).

### Trusting a run

Two things can weaken a result, and both are reported rather than assumed away:

- **Regex engine.** Matching uses RE2 (linear-time, ReDoS-immune). If the native binding
  cannot load — most often an ABI mismatch after a Node upgrade — the tool falls back to
  the JS engine and says so on stderr, in the table/markdown output, and in `--json`
  (`engine`, `degradedReason`). Use `--require-re2` to exit 2 instead of running degraded,
  and `doctor` to check before you start.
- **Resource ceilings.** Very large inputs can hit a bound in `src/limits.ts`. A run that
  did is labelled `PARTIAL ANALYSIS`, names the ceiling it hit, and sets `truncated` in
  `--json`. Treat its verdicts as a lower bound and re-run over a narrower slice.

## Scope

This is fast triage, not proof. EventLogFile carries no response body, so a `LIKELY_ABUSE`
verdict is a lead to confirm in the DuckDB `forensics-db` layer plus the guest user's
access rights — not evidence of exfiltration. For relational deep-dives (cross-event
joins, sessionization, GraphQL edges-vs-count), use `forensics-db`.

## Scripting and agents

Every command has a machine-readable mode, so a script or an agent can read the tool's
own coverage and logic instead of parsing its prose:

| Command | Returns |
|---|---|
| `analyze --json` | The report — see the [field reference](#json---json). |
| `catalog --json` | `{ family, count, rules: Rule[] }` — every detection rule with its pattern, severity, target and `sfExploitable` flag. |
| `explain --json` | `{ verdicts: [{verdict, severity, meaning}], decisionOrder, scope }` — `severity` is the rank `--fail-on` compares. |
| `doctor --json` | `{ status, node, engine, limits }` — `status` is `"ok"` only when RE2 loaded and Node is in range. |

[AGENTS.md](AGENTS.md) is the condensed contract: invocation, exit codes and output
shapes with none of the rationale above.

## Development

```bash
pnpm install        # prepare builds dist/
pnpm build
pnpm test           # vitest, incl. an end-to-end suite over the built CLI
```

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for adding a detection rule and the
trust-boundary rules a change has to respect.

## Documentation

- [AGENTS.md](AGENTS.md) — terse machine-facing contract
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, trust boundary, verdict logic
- [docs/SECURITY.md](docs/SECURITY.md) — threat model and self-defense
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — setup, tests, adding a catalog rule
- [docs/DESIGN.md](docs/DESIGN.md) — the original design spec
- [CHANGELOG.md](CHANGELOG.md)

## License

[Apache-2.0](LICENSE). Issues: <https://github.com/cclabsnz/sfelf-triage/issues>.
