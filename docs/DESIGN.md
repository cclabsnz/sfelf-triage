# Design: `sfelf-triage` — Salesforce EventLogFile forensic triage CLI

- **Date:** 2026-07-17
- **Status:** Draft for review
- **Author:** Gaurav (with Claude)
- **Working name:** `sfelf-triage` (Salesforce Event Log File triage) — final name TBD

## 1. Problem & motivation

When a Salesforce security alert fires on guest/community traffic (e.g. "account X flagged
for Log4j exploitation from these IPs"), the only fast way to answer *"is this a scanner or a
real threat?"* today is to hand-run the `forensics-db/` DuckDB scripts and eyeball the URIs.
That worked for a real guest-traffic incident (confirmed a benign Nessus vuln
scan), but it is manual, DuckDB-dependent, and the interpretation lives in an analyst's head.

We want a standalone tool that ingests already-downloaded EventLogFile CSVs (downloaded **by
any means** — `sf audit events pull`, `curl`, `sf api request`) and runs them against a
maintained catalog of **all known exploit methods/patterns**, emitting a per-IP triage verdict
plus supporting evidence.

## 2. Goals / non-goals

**Goals**
- Point the tool at a directory of EventLogFile CSVs; get a per-IP verdict + evidence tables.
- No Salesforce org connection required — pure local file analysis.
- Cover **both** pattern classes: generic web-exploit probes *and* Salesforce-specific
  guest/community abuse.
- Reuse open-source rule data (OWASP CRS) and libraries rather than hand-writing signatures.
- Be safe to run against hostile input and against sensitive health data (zero runtime egress).

**Non-goals**
- Does **not** replace `forensics-db/` — that remains the DuckDB relational deep-dive
  (cross-event-type joins, sessionization, GraphQL edges-vs-count). When triage says "go
  deeper," it points the analyst there.
- Does **not** become part of the `@cclabsnz/sf-audit` posture plugin. That plugin audits
  configuration; this tool analyzes logs. Separate tools, separate responsibilities.
- Does **not** download logs. Collection is out of scope (done by `sf audit events pull` etc.).

## 3. Architecture

A pipeline of small, independently-testable units, wrapped by a single trust boundary so that
hostile-input handling is a *layer*, not a cross-cutting concern.

```
 raw CSV bytes ─▶ [ Sanitizer.ingress ] ─▶ SafeEvent ─▶ pure core ─▶ value ─▶ [ Sanitizer.egress ] ─▶ out
   (untrusted)                                          match·correlate·score
                                    the core only ever touches SafeEvent, never raw bytes
```

Stage flow inside the core:

```
discover → ingest(stream) → normalize → match(catalog) → correlate → score → report
```

- **discover** — scan input dir, map `EventType-YYYY-MM-DD.csv` filenames → EventType + date
  (reuses the naming convention `forensics-db/collect.mjs` already writes).
- **ingest** — `csv-parse` streaming (RFC-4180, handles quoted embedded newlines); constant
  memory; yields one raw row at a time.
- **normalize** — map each EventType's columns onto a unified event shape.
- **match** — run each event's URI/query fields against the pattern catalog via `SafeMatcher`.
- **correlate** — bounded in-memory index for the few relational patterns (read-then-download,
  REQUEST_ID layer-stack, IP+time sessionization).
- **score** — per-IP verdict from matches + behavioral flags.
- **report** — render via `Sanitizer.egress` to table / JSON / markdown.

## 4. The trust boundary (hostile-input layer)

Three single-responsibility units hold **all** hostile-input logic. Everything else is pure and
security-free.

### 4.1 `Sanitizer.ingress(rawRow) → SafeEvent`
- The *only* code that touches raw file bytes.
- Responsibility: turn untrusted bytes into a bounded, decoded, typed value — multi-pass
  URL-decode, cap field lengths, tag.
- `SafeEvent` is a **branded/immutable type** the core cannot construct any other way. Holding a
  `SafeEvent` structurally guarantees it has been sanitized; downstream stages never re-implement
  guards.

### 4.2 `SafeMatcher.run(pattern, field) → Match`
- The *only* code that executes a pattern against untrusted text.
- Responsibility: run a regex without ReDoS. **RE2 primary** (linear-time, immune); **pure-JS
  `RegExp` fallback** under a hard per-match timeout + input-length cap when the native binding
  can't build. The catalog and match-orchestration call this; they never touch `RegExp` directly.

### 4.3 `Sanitizer.egress(value) → printable`
- The *only* code that writes to terminal/file.
- Responsibility: neutralize before emit — strip ANSI/control chars, prefix-guard CSV formula
  cells (`= + @ -`). Every renderer goes through it; renderers stay dumb.

### 4.4 Discipline (applies inside the units above)
- Payloads are opaque bytes: never passed to a template engine, `eval`, shell, or an
  interpolating logging framework. (`${jndi:…}` is inert in Node; the discipline prevents future
  foot-guns.)
- GraphQL/SOQL query text is attacker-controlled: bound input size + parse depth, wrap parsing in
  try/catch, treat parse failure as "unparsed — flag it," never crash.
- Path safety: reads confined to the given input dir (resolve + prefix-check); output paths
  sanitized.

## 5. The pattern catalog (core asset)

A **versioned, extensible** catalog. Each rule:

```
{ id, family, source: "CRS:<id>" | "custom", severity,
  target: "uri" | "query" | "header", matcher: regex | fn,
  sfExploitable: boolean, note }
```

`sfExploitable` is the flag that separates scanner noise from real abuse in the verdict.

**Class 1 — generic web probes** (seeded from OWASP CRS v4, Apache-2.0; `sfExploitable: false`):
Log4Shell JNDI (all obfuscations) + Log4j config-grab, LFI / path traversal, RFI / SSRF
(CORS-proxy, OOB canary domains `*.nessus.org` / `interact.sh` / `oastify.com`), CRLF / header
injection, Struts2 OGNL, Spring Actuator, Pentaho LDAP, Oracle Reports rwservlet, exposed
`.git` / `.env` / CI files, WordPress probes. These mean "you are being scanned."

**Class 2 — Salesforce-specific guest/community abuse** (authored from the
`sf-guest-access-forensic-sources` knowledge; `sfExploitable: true`):
guest GraphQL/Aura bulk read (`edges` collection-read vs `totalCount` recon — entity from query
text), Aura `ApexActionController` data-controller abuse vs login-only traffic, list-view /
report recon, bulk object reads, **read-then-download** correlation (file-object read →
`ContentTransfer` within N seconds = byte exfil), datacenter-IP / off-hours / high-rate guest
sessions.

CRS Class-1 data is **vendored at build time from a pinned CRS release tag with checksum
verification**, code-reviewed to the subset we import — never fetched at runtime.

### 5.1 Discovery is unfiltered-first; signatures only categorize

Signature matching is a categorization step, **not** the discovery mechanism — a keyword filter
can only find *known* patterns and would silently miss a novel probe. The tool therefore surfaces
anomalies **before and independent of** the catalog:

- **Volume + distinct-URI anomaly** — an actor hitting thousands of distinct paths (the 4 IPs hit
  3,756 distinct URIs) is abnormal regardless of any signature. Reported per IP up front.
- **Behavioral profile** — login-only vs data-controller ratio, request rate, off-hours,
  datacenter IP. Signature-independent.
- **The `other` bucket is always shown** — requests matching no known signature are surfaced, not
  hidden, so an unrecognized attack is visible as "unclassified anomalous traffic."

The catalog then labels *what kind* of attack the surfaced traffic is. The verdict never depends
on the family labels alone; the behavioral layer is the backstop that flags "this actor is
abnormal" even when nothing matches.

## 6. Output

Per-IP verdict: `BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE`, driven by whether matches are
Class-1-only (→ scanner) vs Class-2 behavioral (→ real abuse). Evidence tables underneath
(families, timeline, top endpoints), mirroring the tables produced manually for the 2026-07-15
incident. Flags: `--json` (pipelines), `--md` (incident record), `--redact` (mask record
IDs/tokens in shared output).

### 6.1 Response-return signals & their limits

The verdict must answer not just "was this attacked?" but "did anything come back?" EventLogFile
records response **metadata**, never the response **body** — so return is *inferred*, not read.

**Available signals** (per request, where the EventType carries them): `RESPONSE_SIZE` (bytes
returned), `IS_ERROR` (request faulted), `REQUEST_STATUS`, `ROWS_PROCESSED`.

**Scoring rules:**
- `IS_ERROR = true` (RESPONSE_SIZE 0) → nothing served; the request was rejected.
- **`RESPONSE_SIZE` uniformity check** — when matched requests across *different* attack families
  return the *same* byte sizes (e.g. the platform's canned 404 / login HTML, identical max across
  Log4Shell, LFI, rwservlet), that is the standard error page, not endpoint-specific data →
  supports `BENIGN_SCANNER`.
- **Size-vs-expectation check** — a response size that is the wrong order of magnitude for a
  successful exploit is exculpatory (e.g. a real `/etc/passwd` leak is ~KB of text; a 37 KB
  branded HTML page is the 404, not the file).
- Variable / large responses on genuine **data controllers** (Class-2 endpoints) → escalate to
  `SUSPICIOUS` / `LIKELY_ABUSE`.

**Confidence honesty rule (mandatory):** for data-read questions the tool **bounds, does not
prove**. When it cannot establish content return from EventLogFile alone, the verdict states so
explicitly — e.g. *"no data-return signature observed; content not provable from EventLogFile;
confirm via forensics-db + guest access rights."* It triangulates (`RESPONSE_SIZE` anomaly +
query shape `edges`-vs-`totalCount` + guest access rights + follow-on `ContentTransfer`) and
**never claims proof it does not have.** A `BENIGN_SCANNER` verdict is asserted only when probes
are Class-1-only AND every response is an error or a canned-page size.

## 7. Open-source building blocks

| Concern | Library | Notes / caveat |
|---|---|---|
| CSV ingest | `csv-parse` (adaltas/node-csv) | RFC-4180 streaming; handles quoted newlines |
| Class-1 signatures | OWASP CRS v4 rule data (Apache-2.0) | vendored, pinned, checksummed; not hand-written |
| Regex engine | `re2` | linear-time, ReDoS-safe; **only** native dep (build allowlist) |
| GraphQL entity extraction | `graphql` (reference parser) | parse guest GraphQL query text → entities / edges vs totalCount |
| SOQL parsing | `@jetstreamapp/soql-parser-js` | parse ApiEvent/RestApi SOQL for entity / row-count recon |
| CIDR / cloud attribution | `ipaddr.js` + bundled AWS/Azure/GCP IP-range JSON | flag datacenter/cloud guest traffic; snapshots, not live fetch |
| CLI / output | `commander`, `cli-table3`, `chalk` | standard, lightweight |
| Schema / validation | `zod` | already in the stack |

**Deferred out of v1:** `node-libinjection` — native C lib with a history of detection bypasses;
SQLi/XSS are not the primary Salesforce guest-abuse vectors. Excluded to keep `re2` the sole
native dependency and minimize added attack surface. Revisit if a concrete need appears.

**Rejected as a runtime dependency:** `coraza-node` — preview/experimental, built as
Express/Fastify middleware expecting live HTTP request objects, runs a Go/WASM engine per
request. Wrong shape for bulk log triage. We reuse the CRS *rule data* it would run, not the
engine. Reconsider only as an optional deep-scan mode later.

## 8. Supply-chain & runtime security posture

Orthogonal to the code boundary in §4 — this is build/runtime posture.

- **pnpm + frozen lockfile** with integrity hashes; minimal direct deps, all version-pinned.
- **Native build control:** `ignore-scripts` by default with an explicit `onlyBuiltDependencies`
  allowlist (just `re2`) — no arbitrary postinstall scripts from transitive deps.
- **CI gates:** `pnpm audit` + OSV/Dependabot on every PR (same pattern the sf-audit repo already
  runs), fail on high/critical.
- **Zero runtime egress** (critical — logs contain NZ health PII): the analysis path makes **no
  outbound network calls**. No telemetry, no live IP/threat-intel lookups. Runs identically under
  `--network=none`. All enrichment uses bundled snapshots.
- **Report file perms** restrictive; `--redact` masks record IDs/tokens.

## 9. Module map

```
sanitizer/     ingress + egress  ── the trust boundary (hostile input)
matcher/       SafeMatcher       ── the only untrusted-regex executor
core/          normalize·match·correlate·score  ── pure logic over SafeEvent
catalog/       Class-1 (CRS) + Class-2 (SF) rules + loader
report/        table·json·md renderers (dumb; call egress)
cli/           commander entrypoint, arg parsing
```

## 10. Testing strategy

- **Boundary units get adversarial tests:** feed the entire Class-1 payload set through
  `Sanitizer` + `SafeMatcher`; assert no ReDoS timeout, no ANSI/control leak in egress output, no
  CSV formula execution. The analyzer proves it survives its own signature set (self-dogfooding).
- **Core gets plain logic tests** on safe fixtures — no security assertions needed there.
- **Golden fixtures:**
  - the benign-scan golden fixture (a trimmed CSV set) → must output `BENIGN_SCANNER` for the
    four AWS scanner IPs with the correct family breakdown.
  - the exfil-cluster golden fixture (GraphQL edges-read IPs) → must output `LIKELY_ABUSE`.
- Unit tests per stage with mocked rows; `csv-parse` fixture with an embedded-newline CRLF payload
  row to prove ingest correctness (the case that broke naive `split('\n')`).

## 11. Open questions / future

- Final tool name and repo location (in `sf-incident` vs its own repo).
- Optional `coraza-node` deep-scan mode (post-v1).
- Whether `forensics-db` should later read the same catalog file (shared signature source).
