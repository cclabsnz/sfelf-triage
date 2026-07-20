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

The tool must process all of it without being exploited, and without leaking any of it
in a way that harms the analyst's terminal, a spreadsheet, or a downstream pipeline.

## Defenses

**Single trust boundary.** All hostile-input handling lives in three units, so there is
one place to audit each concern:

- `sanitizer/ingress.ts` is the only code that touches raw bytes. It URL-decodes without
  throwing on malformed input, and caps every field to `MAX_FIELD` (8192 bytes). The cap
  bounds every downstream regex, so even the JS fallback matcher cannot be driven into a
  pathological backtrack.
- `matcher/safeMatcher.ts` is the only code that runs a regex against untrusted text. It
  prefers RE2, which is linear-time and immune to ReDoS. When the native binding is
  unavailable it falls back to JS `RegExp` on the already-capped input.
- `sanitizer/egress.ts` is the only code that writes output. It strips ANSI escape
  sequences and control characters (so a payload cannot spoof or corrupt the terminal),
  and prefix-guards CSV formula cells.

**No interpolation of payloads.** Payload strings are treated as opaque data. They are
never passed to a template engine, `eval`, `new Function`, a shell, or an interpolating
logger. (`${jndi:...}` is inert in Node, but the discipline prevents any future foot-gun.)

**Bounded parsing.** CSV parsing streams with constant memory. Match patterns come only
from the tool's own catalog, never from user input.

**Branded types.** `SafeEvent` can only be constructed by `ingress`. The core cannot
receive an unsanitized event, and this is enforced structurally by the type, not by
convention.

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

The analyzer proves it survives its own signature set on every CI run.

## Supply chain

- pnpm with a committed lockfile; CI runs `pnpm install --frozen-lockfile`.
- `.npmrc` sets `ignore-scripts=true`; only `re2` is allowed to run an install script,
  via `pnpm.onlyBuiltDependencies`. `re2` is the sole native dependency.
- CI runs `pnpm audit --prod --audit-level=high`. Build-only advisories in `re2`'s
  compile chain (`node-gyp` → `tar`) are allowlisted in `package.json`
  (`pnpm.auditConfig.ignoreGhsas`) with per-entry notes; any new high/critical in the
  runtime dependency graph still fails the gate.

## Scope and honesty

This tool bounds, it does not prove. EventLogFile has no response body, so a
`LIKELY_ABUSE` verdict is a lead to confirm elsewhere (the DuckDB `forensics-db` layer,
plus the guest user's access rights at the time), not evidence that data was exfiltrated.
Treat verdicts accordingly.

## Reporting a vulnerability

If you find a security issue in the tool itself, please report it privately to the
maintainer rather than opening a public issue.
