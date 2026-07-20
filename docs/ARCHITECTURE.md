# Architecture

`sfelf-triage` reads downloaded Salesforce EventLogFile CSVs and produces a per-IP
verdict. It never connects to an org and makes no network calls — collection happens
elsewhere (`sf audit events pull`, `curl`), and this tool only analyzes the files.

## Pipeline

```
discover → ingest → match → correlate → score → report
```

- **discover** (`core/discover.ts`) — scans the input directory for files named
  `<EventType>-YYYY-MM-DD.csv` (e.g. `Sites-2026-07-15.csv`), ignoring anything else.
  Reads are confined to the given directory.
- **ingest** (`core/ingest.ts`) — streams each CSV with `csv-parse` (RFC-4180, so a
  quoted field containing a newline stays one record), yielding one row at a time.
  Constant memory, so a 500 MB daily log is fine.
- **match** (`core/match.ts`) — runs each event's URI / query / action field against the
  catalog through `SafeMatcher`. Field selection is by `rule.target`.
- **correlate** (`core/correlate.ts`) — the one relational check: a guest file-object
  read followed by a `ContentTransfer`/`ContentDistribution` download from the same IP
  within a time window. Uses a bounded per-IP index, not an all-pairs scan.
- **score** (`core/score.ts`) — aggregates matches per IP into a verdict (see below).
- **report** (`report/*.ts`) — renders table / JSON / markdown, plus the `catalog` and
  `explain` views. All output is routed through `egress`.

## The trust boundary

This tool ingests hostile input by definition — every row may carry a live Log4Shell
string, path traversal, a CRLF payload, or a ReDoS pattern. Rather than sprinkle guards
through every stage, all hostile-input handling lives in three single-responsibility
units that wrap a pure core:

```
 raw CSV bytes ─▶ [ Sanitizer.ingress ] ─▶ SafeEvent ─▶ pure core ─▶ value ─▶ [ Sanitizer.egress ] ─▶ out
   (untrusted)                                          match·correlate·score
```

- **`sanitizer/ingress.ts`** — the only code that touches raw file bytes. URL-decodes
  (multi-pass, never throws), caps every field to `MAX_FIELD` (8192 bytes), and stamps
  the `SafeEvent` brand. Downstream code can only obtain a `SafeEvent` from here, so
  holding one is a structural guarantee that it was sanitized.
- **`matcher/safeMatcher.ts`** — the only code that runs a regex against untrusted text.
  Prefers RE2 (linear-time, ReDoS-immune); falls back to JS `RegExp` on length-capped
  input when the native binding is unavailable.
- **`sanitizer/egress.ts`** — the only code that prepares a string for output. Strips
  ANSI escape sequences and control characters, and prefix-guards CSV formula cells.

The core (`discover → … → score`) is pure logic over `SafeEvent`. It carries no
sanitization code, which keeps it small and easy to reason about.

## The catalog

`catalog/` holds the detection rules — the tool's core asset. Each rule is a `Rule`
object: `{ id, family, source, severity, target, pattern, sfExploitable, note }`.

- **Class 1** (`catalog/class1.ts`, `sfExploitable: false`) — generic web-exploit probes
  (Log4Shell, LFI, RFI/SSRF, CRLF, Struts2, Spring Actuator, Pentaho, Oracle Reports,
  exposed `.git`/`.env`). These are inert on Salesforce; a match means "you are being
  scanned."
- **Class 2** (`catalog/class2.ts`, `sfExploitable: true`) — Salesforce guest/community
  abuse (GraphQL bulk read, Apex data-controller invocation, list-view recon). A match
  means behaviour that can touch real data on this platform.

Run `sfelf-triage catalog` to list every rule.

## Verdict logic

`score` decides in this order (the order is load-bearing):

1. **`LIKELY_ABUSE`** — the IP has any `sfExploitable` match OR any read-then-download
   correlation.
2. **`SUSPICIOUS`** — it has matches, but the responses were not all errors or canned
   pages (a real content-sized response came back).
3. **`BENIGN_SCANNER`** — Class-1-only matches AND every matched response was an error
   or a canned platform page.

The canned-page heuristic: a `RESPONSE_SIZE` seen three or more times among an IP's
matched responses is treated as a stock platform page (a 404 / login), not data.

**Bounds, not proves.** EventLogFile carries no response body, so the tool can never
read what was returned. A `LIKELY_ABUSE` verdict is a lead to confirm in the DuckDB
`forensics-db` layer plus guest access rights — it is not proof of exfiltration, and
every verdict says so in its confidence note.

## Module map

```
sanitizer/   ingress + egress          the trust boundary
matcher/     safeMatcher               the only untrusted-regex executor
catalog/     class1 + class2 + index   detection rules
core/        discover · ingest · match · correlate · score · analyze
report/      render · catalogView · explain   (all via egress)
cli.ts       commander entrypoint
types.ts     SafeEvent (branded), Rule, Match, IpVerdict, Verdict
```
