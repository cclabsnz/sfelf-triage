# Contributing

## Setup

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

The project is ESM TypeScript. Local imports use `.js` extensions (`import { x } from
'./y.js'`) even though the source is `.ts` — that is required by NodeNext resolution.

## Tests

Tests run with vitest and live next to the code they cover (`*.test.ts`).

```bash
pnpm test                         # full suite
pnpm vitest run src/core/score.test.ts   # one file
pnpm vitest                       # watch mode
```

Write the test first, watch it fail, then implement. Keep test output clean — no stray
logs or warnings.

## Adding a detection rule

Rules are the tool's core asset, and they are just data. To add one:

1. Pick the class:
   - `src/catalog/class1.ts` for a generic web-exploit probe (`sfExploitable: false`).
   - `src/catalog/class2.ts` for Salesforce guest/community abuse (`sfExploitable: true`).
2. Append a `Rule` object:

   ```ts
   { id: 'c1-example', family: 'Example', source: 'CRS:xxxxxx' | 'custom',
     severity: 'low' | 'medium' | 'high' | 'info',
     target: 'uri' | 'query' | 'action' | 'header',
     pattern: String.raw`your-regex-here`,
     sfExploitable: false, note: 'One line on what this catches.' }
   ```

   - `id` must be unique.
   - `pattern` is a regex source string. Use `String.raw` so backslashes are literal. It
     is run only through `SafeMatcher`, never compiled directly — do not add a `new
     RegExp` anywhere outside `matcher/safeMatcher.ts`.
   - `target` selects which field the pattern runs against (`uri`/`header` → the URI,
     `query` → the query text, `action` → the Aura action message).
3. Add a test in `src/catalog/index.test.ts` asserting your pattern matches a
   representative payload and does not match benign traffic.
4. Run `pnpm test`. `sfelf-triage catalog` will list your rule automatically.

## Trust-boundary rules

These are non-negotiable — the tool processes hostile input:

- Only `sanitizer/ingress.ts` touches raw bytes (decode / cap).
- Only `matcher/safeMatcher.ts` runs a regex against untrusted text.
- Only `sanitizer/egress.ts` writes output. Renderers stay dumb and route through it.
- Never pass a payload string to a template engine, `eval`, a shell, or an interpolating
  logger.
- No outbound network calls in the analysis path. The tool must run under `--network=none`.

## Before you open a PR

```bash
pnpm build          # tsc must be clean
pnpm test           # full suite green
pnpm audit --prod --audit-level=high
```
