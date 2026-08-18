#!/usr/bin/env node
import { createRequire } from 'node:module';
import { Command } from 'commander';
import { analyze } from './core/analyze.js';
import { discover } from './core/discover.js';
import { loadCatalog } from './catalog/index.js';
import { evaluateGate, isVerdict } from './gate.js';
import { DEFAULT_LIMITS } from './limits.js';
import { SafeMatcher } from './matcher/safeMatcher.js';
import { renderJson, renderTable, renderMarkdown } from './report/render.js';
import { egress } from './sanitizer/egress.js';
import { VERDICTS, type Verdict } from './types.js';
import { renderCatalog } from './report/catalogView.js';
import { explainVerdict } from './report/explain.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string };

const program = new Command();
program
  .name('sfelf-triage')
  .description(
    'Forensic triage for downloaded Salesforce EventLogFile CSVs.\n' +
      'Matches guest/community traffic against an exploit + abuse catalog and emits a\n' +
      'per-IP verdict (BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE). No org connection,\n' +
      'zero network egress — safe to run on sensitive logs and air-gapped hosts.',
  )
  .version(pkg.version, '-v, --version', 'print version and exit')
  .showHelpAfterError('(run "sfelf-triage --help" for usage)');

program
  .command('analyze')
  .description('analyze a directory of EventLogFile CSVs and print per-IP verdicts')
  .argument('<dir>', 'directory of downloaded EventLogFile CSVs (e.g. Sites-2024-01-15.csv)')
  .option('--json', 'emit JSON (machine-readable, for pipelines)')
  .option('--md', 'emit a markdown table (for the incident write-up)')
  .option(
    '--require-re2',
    'fail instead of falling back to the JS regex engine (for unattended pipelines)',
  )
  .option(
    '--fail-on <verdict>',
    'exit non-zero when any IP reaches this verdict (BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE)',
  )
  .option(
    '--max-rows <n>',
    'stop after n rows — a fast sample pass; the run then reports as PARTIAL',
  )
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage analyze ./logs                 # table (default)
  $ sfelf-triage analyze ./logs --json          # JSON for pipelines
  $ sfelf-triage analyze ./logs --md            # markdown for an incident record
  $ sfelf-triage analyze ./logs --require-re2   # refuse to run without RE2

Gating a pipeline on the result:
  $ sfelf-triage analyze ./logs --fail-on LIKELY_ABUSE
  $ sfelf-triage analyze ./logs --fail-on SUSPICIOUS --require-re2

Get the logs first with:
  $ sf audit events pull -o <org> --since 7 --output ./logs

Exit codes:
  0  analysis ran (and, with --fail-on, nothing reached the threshold)
  1  error — missing/unreadable dir, no CSVs, bad argument
  2  --require-re2 was given but the native RE2 engine is unavailable
  3  --fail-on threshold met — one or more IPs reached that verdict
  4  --fail-on threshold not met, but the run was truncated at a resource ceiling,
     so "nothing found" is not a clean result`,
  )
  .action(async (
    dir: string,
    opts: {
      json?: boolean;
      md?: boolean;
      requireRe2?: boolean;
      failOn?: string;
      maxRows?: string;
    },
  ) => {
    // Validate arguments before the scan: a typo must not surface as a green gate after
    // a long run.
    let threshold: Verdict | null = null;
    if (opts.failOn !== undefined) {
      const wanted = opts.failOn.toUpperCase();
      if (!isVerdict(wanted)) {
        process.stderr.write(
          `sfelf-triage: --fail-on expects one of ${VERDICTS.join(', ')}, got "${egress(opts.failOn)}".\n`,
        );
        process.exit(1);
      }
      threshold = wanted;
    }

    let limits = DEFAULT_LIMITS;
    if (opts.maxRows !== undefined) {
      const n = Number(opts.maxRows);
      if (!Number.isInteger(n) || n <= 0) {
        process.stderr.write(
          `sfelf-triage: --max-rows expects a positive integer, got "${egress(opts.maxRows)}".\n`,
        );
        process.exit(1);
      }
      limits = { ...DEFAULT_LIMITS, maxRows: n };
    }

    const files = await discover(dir).catch(() => []);
    if (files.length === 0) {
      process.stderr.write(
        `sfelf-triage: no EventLogFile CSVs found in "${dir}".\n` +
          'Files must be named like "Sites-2024-01-15.csv". Download them with:\n' +
          `  sf audit events pull -o <org> --since 7 --output ${dir}\n`,
      );
      process.exit(1);
    }

    // Check the engine before doing the work, so --require-re2 fails fast rather than
    // after a long scan whose results the caller has already said it will not accept.
    const matcher = new SafeMatcher();
    if (opts.requireRe2 && matcher.engine !== 're2') {
      process.stderr.write(
        `sfelf-triage: --require-re2 given but RE2 is unavailable: ${matcher.degradedReason}\n`,
      );
      process.exit(2);
    }

    const report = await analyze(dir, { matcher, limits });

    // The engine warning also goes to stderr for the table/markdown paths, which carry it
    // in-band: piping stdout to a file must not be able to lose the caveat.
    if (report.engine !== 're2') {
      process.stderr.write(
        `sfelf-triage: WARNING — running on the JS regex fallback, not RE2: ${report.degradedReason}\n` +
          '  ReDoS immunity is not guaranteed; field caps are the only bound. Pass --require-re2 to make this fatal.\n',
      );
    }
    const limitSummary = report.limits.summary();
    if (limitSummary) process.stderr.write(`sfelf-triage: ${limitSummary}\n`);

    if (opts.json) {
      process.stdout.write(renderJson(report) + '\n');
    } else if (opts.md) {
      process.stdout.write(renderMarkdown(report) + '\n');
    } else if (report.verdicts.length === 0) {
      process.stdout.write('No flagged IPs — no traffic in these logs matched the catalog.\n');
    } else {
      process.stdout.write(renderTable(report) + '\n');
    }

    // The gate runs last so the report is always emitted first: a failing pipeline step
    // should still leave the analyst the findings that failed it.
    if (threshold) {
      const gate = evaluateGate(report, threshold);
      if (gate.message) process.stderr.write(`sfelf-triage: ${gate.message}\n`);
      if (gate.exitCode !== 0) process.exitCode = gate.exitCode;
    }
  });

program
  .command('catalog')
  .description('list the detection rules this tool checks for')
  .option('--family <name>', 'show only one family (e.g. Log4Shell)')
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage catalog
  $ sfelf-triage catalog --family Log4Shell`,
  )
  .action((opts: { family?: string }) => {
    process.stdout.write(renderCatalog(loadCatalog(), opts.family) + '\n');
  });

program
  .command('explain')
  .description('explain what a verdict means and how it is decided')
  .argument('[verdict]', 'BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE (omit to explain all)')
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage explain
  $ sfelf-triage explain LIKELY_ABUSE`,
  )
  .action((verdict?: string) => {
    process.stdout.write(explainVerdict(verdict) + '\n');
  });

program.addHelpText(
  'after',
  `
Commands at a glance:
  analyze <dir>      triage a directory of EventLogFile CSVs → per-IP verdicts
  catalog            list what the tool detects (Class 1 scanner probes, Class 2 SF abuse)
  explain [verdict]  what the verdicts mean and how they are decided

This is fast triage, not proof. For deep relational forensics (cross-event joins,
GraphQL edges-vs-count, sessionization) use the DuckDB forensics-db layer. A
LIKELY_ABUSE verdict is a lead to confirm there, not evidence of exfiltration.`,
);

// With no subcommand, show help rather than exiting silently.
if (process.argv.length <= 2) {
  program.help();
}

program.parseAsync().catch((err) => {
  process.stderr.write(`sfelf-triage: ${String(err)}\n`);
  process.exit(1);
});
