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

Run `sfelf-triage explain` for the full decision logic.

## Install

Requires Node `^22.22.2 || ^24.15.0 || >=26.0.0` — the range `re2` supports. Node 20 is
not supported: it reached end of life on 2026-04-30, and the `re2` versions that carry
no open advisories do not run on it.

```bash
pnpm install --frozen-lockfile
pnpm build
```

Optionally make it invokable as `sfelf-triage` from anywhere:

```bash
pnpm link --global
```

(The examples below use `node dist/cli.js`; substitute `sfelf-triage` if you linked it.)

## Commands

```bash
# Triage a directory of logs
node dist/cli.js analyze ./logs            # table (default)
node dist/cli.js analyze ./logs --json     # JSON for pipelines
node dist/cli.js analyze ./logs --md       # markdown for an incident record

# Learn what the tool does — it documents itself
node dist/cli.js catalog                   # list every detection rule it checks
node dist/cli.js catalog --family Log4Shell
node dist/cli.js explain                   # what every verdict means + how it's decided
node dist/cli.js explain LIKELY_ABUSE

node dist/cli.js --help                    # top-level help
node dist/cli.js analyze --help            # per-command help + examples
node dist/cli.js --version
```

Get the logs first with (any download method works; the tool only needs the CSVs):

```bash
sf audit events pull -o <org> --since 7 --output ./logs
# then point the analyzer at the org's baseline directory:
node dist/cli.js analyze ~/.sf/event-baseline/<orgId>
```

`discover` reads two layouts, recursively:

- flat `<EventType>-YYYY-MM-DD.csv` (e.g. `Sites-2024-01-15.csv`) — the convention the
  `forensics-db` collector and manual downloads use;
- the [sf-audit plugin](https://github.com/cclabsnz/sf-audit-plugin)'s nested
  `~/.sf/event-baseline/<orgId>/<EventType>/<YYYY-MM-DD>-<Id>.csv` layout (the plugin's
  `_manifests/` directory is ignored).

### Gating a pipeline

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
| `1` | error — missing/unreadable dir, no CSVs, bad argument |
| `2` | `--require-re2` given but the native RE2 engine is unavailable |
| `3` | `--fail-on` threshold met — one or more IPs reached that verdict |
| `4` | `--fail-on` threshold not met, but the run was truncated at a resource ceiling |

`4` is deliberately distinct from `0`. A gate has three answers, not two: something was
found, nothing was found, and the run was not complete enough to say. Treating the third
as a pass is how a truncated analysis becomes a false all-clear.

## Example

```
$ node dist/cli.js analyze ./logs --json
{
  "engine": "re2",
  "degradedReason": null,
  "truncated": false,
  "limitsReached": {},
  "stats": { "files": 3, "rows": 41207 },
  "verdicts": [
    {
      "ip": "203.0.113.10",
      "verdict": "BENIGN_SCANNER",
      "totalReqs": 5,
      "distinctUris": 5,
      "distinctUrisTruncated": false,
      "families": { "LFI": 1, "Log4Shell": 1, "Oracle-Reports": 2 },
      "sfExploitableHits": 0,
      "confidence": "No data-return signature observed; content not provable from EventLogFile alone."
    }
  ]
}
```

The verdicts sit under a `verdicts` key rather than at the top level so a consumer can
see, in the same document, which engine produced them and whether the run was complete.

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
  (`engine`, `degradedReason`). Use `--require-re2` to exit 2 instead of running degraded.
  Fix a fallback with `pnpm rebuild re2`.
- **Resource ceilings.** Very large inputs can hit a bound in `src/limits.ts`. A run that
  did is labelled `PARTIAL ANALYSIS`, names the ceiling it hit, and sets `truncated` in
  `--json`. Treat its verdicts as a lower bound and re-run over a narrower slice.

## Scope

This is fast triage, not proof. EventLogFile carries no response body, so a `LIKELY_ABUSE`
verdict is a lead to confirm in the DuckDB `forensics-db` layer plus the guest user's
access rights — not evidence of exfiltration. For relational deep-dives (cross-event
joins, sessionization, GraphQL edges-vs-count), use `forensics-db`.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — pipeline, trust boundary, verdict logic
- [docs/SECURITY.md](docs/SECURITY.md) — threat model and self-defense
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — setup, tests, adding a catalog rule
- [docs/DESIGN.md](docs/DESIGN.md) — the original design spec
- [CHANGELOG.md](CHANGELOG.md)

## License

[Apache-2.0](LICENSE).
