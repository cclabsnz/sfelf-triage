# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses semantic versioning.

## [Unreleased]

### Added
- CLI subcommands: `analyze <dir>`, `catalog`, and `explain`.
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
