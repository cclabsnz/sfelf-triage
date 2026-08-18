# Security

`sfelf-triage` is a security tool that analyzes hostile input. Its own attack surface
matters as much as its findings: every log row it parses may contain a live exploit
payload. This document describes how the tool defends itself, and how to report a
vulnerability.

## Threat model

The input is untrusted by definition. A single EventLogFile row can carry:

- Log4Shell `${jndi:...}` strings and their obfuscations
- path-traversal and LFI payloads (`/etc/passwd`, `..%2f`)
- CRLF / header-injection sequences and ANSI escape codes
- catastrophic-backtracking (ReDoS) input
- CSV formula-injection cells (`=`, `+`, `@`, `-`)
- markdown table delimiters (`|`) aimed at the incident write-up
- volume: enough rows, IPs, URIs or nesting to exhaust memory or CPU

The tool must process all of it without being exploited, and without leaking any of it
in a way that harms the analyst's terminal, a spreadsheet, or a downstream pipeline.

## Defenses

**Single trust boundary.** All hostile-input handling lives in three units, so there is
one place to audit each concern:

- `sanitizer/ingress.ts` is the only code that touches raw bytes. It URL-decodes without
  throwing on malformed input, and caps every field to `MAX_FIELD` (8192 bytes). The cap
  bounds every downstream regex, so even the JS fallback matcher cannot be driven into a
  pathological backtrack. It also canonicalizes `CLIENT_IP`: every per-IP counter and
  threshold is keyed on that string, so a host able to reach the org as both
  `203.0.113.9` and `::ffff:203.0.113.9` could otherwise split its own activity across
  two report rows and sit under the thresholds that would flag it. Canonicalization is
  restricted to rewrites that are provably lossless (IPv4-mapped IPv6, IPv6 spelling).
  Legacy IPv4 notations are **not** resolved even though the parser understands them —
  `0203.0.113.9` is octal for `131.0.113.9` and `2130706433` is `127.0.0.1`, and printing
  those would put an address in the incident record that appears nowhere in the log,
  attributing activity to a host that was never seen. Ambiguous values are kept exactly
  as written so the report always reconciles with its source.
- `matcher/safeMatcher.ts` is the only code that runs a regex against untrusted text. It
  prefers RE2, which is linear-time and immune to ReDoS. When the native binding is
  unavailable it falls back to JS `RegExp` on the already-capped input, and says so
  loudly — see **Degradation is visible** below.
- `sanitizer/egress.ts` is the only code that writes output. `egress` strips ANSI escape
  sequences and control characters, so a payload cannot spoof or corrupt the terminal.
  `mdCell` additionally escapes `|` and `\` for the markdown renderer: an unescaped pipe
  is the column delimiter, so a crafted field could otherwise forge or hide values in an
  incident record a reader takes as faithful. `csvCell` prefix-guards spreadsheet formula
  cells; it is exported for callers writing CSV, and is not used by the built-in
  table/JSON/markdown renderers.

**No interpolation of payloads.** Payload strings are treated as opaque data. They are
never passed to a template engine, `eval`, `new Function`, a shell, or an interpolating
logger. (`${jndi:...}` is inert in Node, but the discipline prevents any future foot-gun.)

**Bounded everything.** Analysis is a single streaming pass that retains no events, so
peak memory scales with distinct client-IP cardinality rather than row count. Every
remaining accumulator has an explicit ceiling in `limits.ts` — rows, files, recursion
depth, IPs, URIs per IP, response sizes per IP, correlation candidates per IP, and the
largest record the CSV parser will assemble. Correlation matches by binary search, so a
single IP issuing many reads and downloads cannot drive quadratic work.

Nothing is truncated silently. Reaching any ceiling is recorded and surfaced in every
output format as `PARTIAL ANALYSIS`, naming the ceiling that bit and the value it was set
to; `--json` carries the same detail in `truncated` / `limitsReached`. A partial run must
never be readable as a complete one — that is how an incomplete analysis becomes a false
all-clear.

The same rule governs the pipeline gate. `--fail-on <verdict>` exits `3` when an IP
reaches the threshold, but exits `4` — not `0` — when nothing reached it and the run was
truncated. A gate has three answers (found / not found / could not tell), and only the
middle one is a pass. Findings take precedence over incompleteness: once an IP has
tripped the threshold the run has answered the question.

**Traversal confinement.** `discover` resolves the target directory and never follows
symlinks out of it. Log directories are routinely unpacked from archives supplied by the
party under investigation, so a planted link is a realistic path to reading the analyst's
filesystem, and a link cycle is a realistic way to hang the run.

**Match patterns come only from the tool's own catalog**, never from user input.

**Branded types.** `SafeEvent` can only be constructed by `ingress`. The core cannot
receive an unsanitized event, and this is enforced structurally by the type, not by
convention.

**Degradation is visible.** RE2 is a native binding, and the common failure is an ABI
mismatch after a Node upgrade: the install still looks healthy, but matching silently
drops to a backtracking engine. Because the guarantee this tool advertises is the one
that disappears, the fallback is reported rather than absorbed —

- a warning on stderr naming the cause and the fix (`pnpm rebuild re2`);
- an in-band `DEGRADED` banner in the table and markdown output, so the caveat survives
  a redirect to a file;
- `engine` and `degradedReason` fields in `--json`;
- `analyze --require-re2`, which exits 2 rather than running degraded — the form to use
  in unattended pipelines;
- a CI job that runs `--require-re2` on every supported Node major, which is what keeps
  a future upgrade from shipping a weaker guarantee with a green build.

## Zero network egress

The analysis path makes no outbound network calls — no telemetry, no live threat-intel
or IP lookups. This is a hard requirement: the logs can contain sensitive data (PII, and in
regulated environments far more), and that data must not leave the host.
The tool runs identically under `--network=none`. Any enrichment data is bundled, not
fetched.

## Self-dogfooding test

`src/security.test.ts` feeds the tool's own Class-1 payload set through the real
catalog, `SafeMatcher`, `ingress`, and `egress`, and asserts that:

- running every rule over every payload completes well under the time bound (no ReDoS hang)
- `egress` output contains no ANSI or control characters

The analyzer proves it survives its own signature set on every CI run. Alongside it, the
suite pins each defense above to a test: traversal confinement and symlink policy
(`core/discover.test.ts`), the streaming/bounded accumulators (`core/score.test.ts`,
`core/correlate.test.ts`), short-read detection (`core/ingest.test.ts`), IP
canonicalization (`sanitizer/ingress.test.ts`), markdown escaping
(`sanitizer/egress.test.ts`), and the degradation diagnostics
(`matcher/safeMatcher.test.ts`).

## Supply chain

- pnpm with a committed lockfile; CI runs `pnpm install --frozen-lockfile`.
- `.npmrc` sets `ignore-scripts=true`; only `re2` is allowed to run an install script,
  via `pnpm.onlyBuiltDependencies`. `re2` is the sole native dependency.
- CI runs `pnpm audit --prod --audit-level=high` on every supported Node major. No
  advisories are allowlisted: any high or critical in the runtime dependency graph fails
  the gate. Build-time transitives in `re2`'s compile chain are pinned forward via
  `pnpm.overrides` instead of being suppressed.
- The runtime dependency set is kept to what is actually imported (`cli-table3`,
  `commander`, `csv-parse`, `ipaddr.js`, `re2`). Unused dependencies are removed rather
  than carried, since each one is shipped attack surface that buys nothing.
- A CI job fails the build if this document describes an audit allowlist that
  `package.json` does not define. Documentation drift on a security control is a
  security bug: this file is what an auditor reads instead of the config.

## Scope and honesty

This tool bounds, it does not prove. EventLogFile has no response body, so a
`LIKELY_ABUSE` verdict is a lead to confirm elsewhere (the DuckDB `forensics-db` layer,
plus the guest user's access rights at the time), not evidence that data was exfiltrated.
Treat verdicts accordingly.

## Reporting a vulnerability

If you find a security issue in the tool itself, please report it privately to the
maintainer rather than opening a public issue.
