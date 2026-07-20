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
```

Files must be named `<EventType>-YYYY-MM-DD.csv` (e.g. `Sites-2026-07-15.csv`) — the
convention the collectors already write. Exit codes: `0` = analysis ran; `1` = error
(missing/unreadable dir, no CSVs).

## Example

```
$ node dist/cli.js analyze ./logs --json
[
  {
    "ip": "13.210.1.103",
    "verdict": "BENIGN_SCANNER",
    "totalReqs": 5,
    "distinctUris": 5,
    "families": { "LFI": 1, "Log4Shell": 1, "Oracle-Reports": 2 },
    "sfExploitableHits": 0,
    "confidence": "No data-return signature observed; content not provable from EventLogFile alone."
  }
]
```

## How it works

A streaming pipeline wrapped by a single trust boundary:

```
discover → ingest → match → correlate → score → report
                    (all hostile-input handling in ingress / SafeMatcher / egress)
```

The tool ingests hostile input by definition, so all decoding, regex execution, and
output live in three single-responsibility units; the core is pure logic over a branded
`SafeEvent`. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/SECURITY.md](docs/SECURITY.md).

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
