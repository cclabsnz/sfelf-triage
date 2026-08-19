# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic versioning.

## [Unreleased]

### Added
- **`doctor`** — one command that answers "is this install healthy, and if not what do I
  run": running Node against the supported range, whether the native RE2 binding loaded
  (with the reason and the remedy when it did not), and the effective resource ceilings.
  Exits `2` when degraded, the same code `--require-re2` uses. `--json` for pipelines.
  The information existed before, spread across a stderr warning that only appears
  mid-analysis, a README section, and the source of `limits.ts`.
- **`--why`** — the per-IP `reasons` the scorer already computed reached `--json` only, so
  the default table showed a verdict with no way to see the evidence behind it short of
  re-running in another format. Now available in the table and markdown views.
- **`-o, --out <file>`** — write the report to a file. An unwritable path is fatal rather
  than a warning: a caller who asked for a file and got exit `0` will believe it is there.
- **`--org <orgId>`** — read `~/.sf/event-baseline/<orgId>` instead of typing the path.
  Validated as a single path segment, so a convenience flag cannot become a traversal.
  Passing both a directory and `--org` is refused rather than resolved by precedence.
- **`catalog --json` and `explain --json`** — the self-documenting commands emitted prose
  only, which is the one format a script or an agent cannot consume. `explain --json`
  carries each verdict's severity rank, so a consumer compares verdicts without
  re-deriving the order `--fail-on` uses.
- **Single-CSV input.** `analyze` accepts a path to one CSV, not only a directory.
  Pointing at a file is the obvious first instinct and previously failed as "no CSVs found".
- **`AGENTS.md`** — the terse machine-facing contract (invocation, exit codes, output
  shapes) with none of the README's rationale.
- **An end-to-end CLI suite** (`src/cli.test.ts`) over the built binary. The unit suites
  covered each piece; the wiring — which flag reaches which renderer, what lands on stdout
  versus stderr, the exit code — was only checked by a shell block in CI that never runs
  on a developer's machine.

### Changed
- **A run that finds no logs now names the CSVs it rejected and what is wrong with each.**
  The old message printed "no EventLogFile CSVs found" over a directory full of CSVs that
  were one character away from matching, and left the analyst to guess which character.
  It now distinguishes an underscore for a hyphen, a `" (1)"` duplicate-download suffix, a
  name carrying no date, and a date-prefixed file whose parent directory is not an
  EventType. The retained sample is bounded — rejected filenames are attacker-shaped input.
- **`explain <unknown-verdict>` exits `1`.** It printed a non-answer and exited `0`, which
  reads as success.
- **`prepare` builds `dist/` on install**, so `npm install -g github:cclabsnz/sfelf-triage`
  produces a working binary. `dist/` is gitignored, so the declared `bin` previously
  pointed at a file a git install never created.
- `package.json` declares `repository`, `homepage` and `bugs`.

### Documentation
- README: corrected the `--json` example, which omitted `reasons` and
  `allResponsesErrorOrCanned` — a consumer coding against it built the wrong parser. Added
  a full field reference for both, a sample of the default table output (only JSON was
  shown), a troubleshooting table, a quick start, and the filename requirement next to
  Install rather than buried below the examples. Settled on one invocation style
  throughout; the old text switched between `node dist/cli.js` and `sfelf-triage`
  mid-document.

### Security
- **Upgraded `re2` 1.21.4 -> 1.26.1**, clearing four open advisories against the one
  dependency that runs against hostile input by design (GHSA-8hcv-x26h-mcgp,
  GHSA-6hxr-mr5r-9836, GHSA-ff84-5f28-78qj, GHSA-j4r3-hg7j-8chg — process-abort and
  out-of-bounds-read DoS, plus a heap-disclosure path). `pnpm audit --prod` now reports no
  known vulnerabilities at any level, down from four moderate.
- **RE2 was never actually in use in CI.** `.npmrc` set `ignore-scripts=true`, which is a
  blanket setting that overrides the `pnpm.onlyBuiltDependencies` allowlist, so re2's
  native binding never compiled — `require('re2')` failed with `MODULE_NOT_FOUND` and the
  matcher silently used the backtracking JS engine. The audit gate had been failing since
  2026-07-26, which skipped the test step, so nothing surfaced it. Removed the blanket
  setting; pnpm 10 blocks dependency scripts by default and the allowlist grants re2 alone.
- **Corrected a false security claim.** `SECURITY.md` stated the `MAX_FIELD` cap meant
  "even the JS fallback matcher cannot be driven into a pathological backtrack". It cannot:
  measured on the JS engine, `(a+)+$` takes 40 ms at 20 characters, 10 s at 30, and does
  not finish at 5000 — four orders of magnitude below the 8192-byte cap. The real property
  is that patterns come only from our catalog and none of them backtrack catastrophically.
  That invariant is now tested directly, against the catalog, on a forced JS-fallback
  matcher, with each pattern in a killable child process (an in-process timeout cannot fire
  while a regex blocks the event loop, so the suite would hang instead of reporting).
- **The RE2 fallback is no longer silent.** When the native binding cannot load — most
  often an ABI mismatch after a Node upgrade, which leaves a healthy-looking install —
  matching dropped to a backtracking JS engine with no indication, quietly retiring the
  ReDoS guarantee the tool advertises. The active engine and the reason for any fallback
  are now reported on stderr, in-band in table/markdown output, and in `--json`.
  `analyze --require-re2` exits 2 rather than running degraded, and CI asserts RE2 is
  active on every supported Node major.
- **Analysis no longer buffers the event stream.** `analyze` retained every `SafeEvent`
  and `MatchedEvent` for the whole run, putting peak memory in proportion to row count
  despite the docs promising constant memory — an out-of-memory failure on exactly the
  multi-gigabyte exports the tool is for. Scoring and correlation now fold incrementally;
  peak memory scales with distinct client-IP cardinality.
- **Every accumulator is bounded** (`src/limits.ts`): rows, files, recursion depth, IPs,
  URIs per IP, response sizes per IP, correlation candidates per IP, and CSV record size.
  Reaching a ceiling is reported as `PARTIAL ANALYSIS` in every format, never truncated
  silently.
- **Oversized CSV records can no longer swallow the rest of a file.** The new
  `max_record_size` ceiling is enforced by csv-parse by ending the stream, which would
  have dropped every later row unreported; ingest compares bytes consumed against file
  size and records a short read.
- **Markdown output escapes `|` and `\`.** An unescaped pipe in a value splits a cell and
  shifts every later column, letting crafted input forge or hide values in an incident
  record (`mdCell`).
- **Client IPs are canonicalized** (`ipaddr.js`). Per-IP counters and thresholds are keyed
  on this string, so a host reaching the org as both `203.0.113.9` and
  `::ffff:203.0.113.9` previously split into two rows and could sit under the thresholds
  that would flag it. Only lossless rewrites are applied: legacy IPv4 notations (octal,
  hex, integer, zero-padded) are deliberately left as written, since resolving them would
  print an address that appears nowhere in the log.
- Pinned `ip-address` forward past GHSA-mwp4-54f8-5fhr, a high in `re2`'s build-time
  `node-gyp` chain that the audit gate had begun failing on.
- **Traversal is confined and terminates.** `discover` resolves the target directory,
  compares by path segment rather than string prefix, does not follow symlinks out of the
  tree, and bounds depth and file count — log directories are routinely unpacked from
  archives supplied by the party under investigation.
- **Correlation matches by binary search**, so a single IP issuing many file reads and
  downloads cannot drive quadratic work in the analyzer.
- Removed unused runtime dependencies `chalk` and `zod`; neither was imported anywhere.

### Changed
- **Breaking:** `engines.node` is now `^22.22.2 || ^24.15.0 || >=26.0.0`, mirroring `re2`'s
  own requirement. **Node 20 is no longer supported**: it reached end of life on
  2026-04-30, and every `re2` release without open advisories requires a newer runtime.
  Supporting it would mean shipping a known-vulnerable regex engine at the trust boundary.
- `@types/node` tracks the minimum supported runtime (20.19.0 -> 22.20.1). It had been
  left describing Node 20 after `engines` moved to `>=22.22.2`, so the build typechecked
  against a runtime the package no longer supports.
- CI runs on Node 22.22.2, 24.15.0 and latest 24 — the floor of each supported range plus
  the moving tip, so an engines claim cannot drift from what is actually tested.
- CI no longer runs twice per push. `on: [push, pull_request]` fires both events for any
  branch with an open PR; push is now scoped to `main`.
- CI asserts the `--fail-on` exit-code contract (0/1/2/3/4) against the fixtures. Pipelines
  gate on those numbers, so a silent change would break a caller without failing a test.
- **Breaking:** `analyze()` returns an `AnalysisReport` (`verdicts`, `engine`,
  `degradedReason`, `limits`, `stats`) instead of a bare `IpVerdict[]`, and `--json`
  emits that object rather than a top-level array. A consumer can now see in one document
  which engine produced the verdicts and whether the run was complete.
- `IpVerdict` gains `distinctUrisTruncated`; a truncated count renders as `>=N`.
- CI runs the full suite on Node 20, 22 and 24, and fails if `docs/SECURITY.md` describes
  an audit allowlist that `package.json` does not define.
- CI declares `permissions: contents: read`, so `GITHUB_TOKEN` is least-privilege; nothing
  in the workflow writes to the repository (flagged by CodeQL
  `actions/missing-workflow-permissions`).
- `docs/SECURITY.md` no longer claims a `pnpm.auditConfig.ignoreGhsas` allowlist — it had
  been removed from `package.json`, leaving the security doc describing a control that no
  longer existed. Build-time transitives are pinned forward with `pnpm.overrides` instead.
- `docs/ARCHITECTURE.md` and `docs/DESIGN.md` corrected: the pipeline never had the
  constant-memory property they described.

### Added
- CLI subcommands: `analyze <dir>`, `catalog`, and `explain`.
- `analyze --require-re2` for unattended pipelines that must not run degraded.
- `analyze --fail-on <verdict>` turns a result into a pipeline failure: exit 3 when any IP
  reaches the threshold (inclusive, ordered `BENIGN_SCANNER < SUSPICIOUS < LIKELY_ABUSE`).
  Exit 4 is returned when nothing reached the threshold *but* the run was truncated at a
  resource ceiling — a gate has three answers, and treating "could not tell" as a pass is
  how a truncated analysis becomes a false all-clear. Findings take precedence over
  incompleteness. Default behaviour is unchanged: without the flag `analyze` still exits 0.
- `analyze --max-rows <n>` for a fast sample pass; the run then reports as `PARTIAL`.
- `.nvmrc` pinning the development toolchain.

### Fixed
- `PARTIAL ANALYSIS` named the *default* ceiling rather than the one the run used, so a
  run bounded to 2 rows reported `maxRows=5000000`. `LimitReport` now holds the limits it
  was constructed with, so the summary cannot describe a run using ceilings it never had.
- `catalog` lists every detection rule (grouped Class 1 / Class 2); `--family` filters.
- `explain [verdict]` describes each verdict, the decision order, and the
  bounds-not-proves caveat.
- `--version`, rich per-command `--help` with examples, and an exit-code contract.
- Teaching error: an empty or missing input directory points the user at
  `sf audit events pull`.
- Documentation: `LICENSE` (Apache-2.0), `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
  `docs/CONTRIBUTING.md`, and an expanded `README`.

## [0.1.0] — 2026-07

### Added
- Initial release. Standalone triage for downloaded Salesforce EventLogFile CSVs.
- Pipeline: `discover → ingest → match → correlate → score → report`.
- Trust boundary: `Sanitizer.ingress` (decode + cap + brand), `SafeMatcher`
  (RE2 with a guarded JS fallback), `Sanitizer.egress` (strip ANSI/control, guard
  CSV formulas).
- Detection catalog: Class 1 generic web-exploit probes and Class 2 Salesforce
  guest/community abuse.
- Per-IP verdicts `BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE` with response-return
  scoring and an honesty note.
- Renderers: table, JSON, markdown.
- Zero network egress; `re2` the only native dependency; self-dogfooding security test.
