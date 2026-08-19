#!/usr/bin/env node
import { createRequire } from 'node:module';
import { writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { Command } from 'commander';
import { analyze } from './core/analyze.js';
import { discoverDetailed } from './core/discover.js';
import { loadCatalog } from './catalog/index.js';
import { evaluateGate, isVerdict } from './gate.js';
import { DEFAULT_LIMITS } from './limits.js';
import { SafeMatcher } from './matcher/safeMatcher.js';
import { renderJson, renderTable, renderMarkdown } from './report/render.js';
import { egress } from './sanitizer/egress.js';
import { VERDICTS, type Verdict } from './types.js';
import { renderCatalog, renderCatalogJson } from './report/catalogView.js';
import { explainVerdict, explainJson } from './report/explain.js';
import { renderDoctor, renderDoctorJson, doctorStatus } from './report/doctor.js';
import { resolveTarget } from './orgDir.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json') as { version: string; engines: { node: string } };

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

/**
 * Send a rendered report to stdout or to `--out`.
 *
 * An unwritable path is fatal rather than a warning: a caller who asked for a file and
 * got a zero exit will believe the file is there.
 */
async function emit(text: string, out: string | undefined): Promise<void> {
  if (out === undefined) {
    process.stdout.write(text + '\n');
    return;
  }
  try {
    await writeFile(out, text + '\n', 'utf8');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`sfelf-triage: could not write "${egress(out)}": ${egress(message)}\n`);
    process.exit(1);
  }
}

program
  .command('analyze')
  .description('analyze a directory of EventLogFile CSVs and print per-IP verdicts')
  .argument(
    '[dir]',
    'directory of downloaded EventLogFile CSVs, or a single CSV (e.g. Sites-2024-01-15.csv)',
  )
  .option('--org <orgId>', 'read ~/.sf/event-baseline/<orgId> instead of passing a directory')
  .option('--json', 'emit JSON (machine-readable, for pipelines)')
  .option('--md', 'emit a markdown table (for the incident write-up)')
  .option('--why', 'add the per-IP reasons behind each verdict')
  .option('-o, --out <file>', 'write the report to a file instead of stdout')
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
  $ sfelf-triage analyze ./logs --why           # table + why each verdict was reached
  $ sfelf-triage analyze ./logs --json          # JSON for pipelines
  $ sfelf-triage analyze ./logs --md --out r.md # markdown, written to a file
  $ sfelf-triage analyze Sites-2024-01-15.csv   # a single CSV works too
  $ sfelf-triage analyze --org 00D...           # read ~/.sf/event-baseline/00D...
  $ sfelf-triage analyze ./logs --require-re2   # refuse to run without RE2

Gating a pipeline on the result:
  $ sfelf-triage analyze ./logs --fail-on LIKELY_ABUSE
  $ sfelf-triage analyze ./logs --fail-on SUSPICIOUS --require-re2

Get the logs first with:
  $ sf audit events pull -o <org> --since 7 --output ./logs

Exit codes:
  0  analysis ran (and, with --fail-on, nothing reached the threshold)
  1  error — missing/unreadable dir, no CSVs, bad argument, unwritable --out
  2  --require-re2 was given but the native RE2 engine is unavailable
  3  --fail-on threshold met — one or more IPs reached that verdict
  4  --fail-on threshold not met, but the run was truncated at a resource ceiling,
     so "nothing found" is not a clean result`,
  )
  .action(async (
    dirArg: string | undefined,
    opts: {
      org?: string;
      json?: boolean;
      md?: boolean;
      why?: boolean;
      out?: string;
      requireRe2?: boolean;
      failOn?: string;
      maxRows?: string;
    },
  ) => {
    const target = resolveTarget({ dir: dirArg, org: opts.org, home: homedir() });
    if (!target.ok) {
      process.stderr.write(`sfelf-triage: ${target.error}\n`);
      process.exit(1);
    }
    const dir = target.dir;

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

    const found = await discoverDetailed(dir, limits).catch(() => null);
    if (found === null || found.files.length === 0) {
      process.stderr.write(noInputMessage(dir, found));
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
          '  ReDoS immunity is not guaranteed; field caps are the only bound. Pass --require-re2 to make this fatal.\n' +
          '  Run "sfelf-triage doctor" for the diagnosis and the fix.\n',
      );
    }
    const limitSummary = report.limits.summary();
    if (limitSummary) process.stderr.write(`sfelf-triage: ${limitSummary}\n`);

    const view = { why: opts.why === true };
    if (opts.json) {
      await emit(renderJson(report), opts.out);
    } else if (opts.md) {
      await emit(renderMarkdown(report, view), opts.out);
    } else if (report.verdicts.length === 0) {
      await emit('No flagged IPs — no traffic in these logs matched the catalog.', opts.out);
    } else {
      await emit(renderTable(report, view), opts.out);
    }

    // The gate runs last so the report is always emitted first: a failing pipeline step
    // should still leave the analyst the findings that failed it.
    if (threshold) {
      const gate = evaluateGate(report, threshold);
      if (gate.message) process.stderr.write(`sfelf-triage: ${gate.message}\n`);
      if (gate.exitCode !== 0) process.exitCode = gate.exitCode;
    }
  });

/**
 * The message for a run that found nothing to analyze.
 *
 * Naming the CSVs that were skipped, and why, is the whole point: the failure this
 * replaces printed "no EventLogFile CSVs found" over a directory full of CSVs that were
 * one character away from matching, and left the analyst to guess which character.
 */
function noInputMessage(
  dir: string,
  found: Awaited<ReturnType<typeof discoverDetailed>> | null,
): string {
  const lines = [`sfelf-triage: no EventLogFile CSVs found in "${egress(dir)}".`];

  if (found && found.rejectedTotal > 0) {
    lines.push(`  Saw ${found.rejectedTotal} .csv file(s), none of them recognized:`);
    const width = Math.max(...found.rejected.map((r) => r.name.length));
    for (const r of found.rejected) {
      lines.push(`    ${egress(r.name).padEnd(width)}  -> ${egress(r.reason)}`);
    }
    const hidden = found.rejectedTotal - found.rejected.length;
    if (hidden > 0) lines.push(`    ...and ${hidden} more`);
  } else if (found) {
    lines.push('  No .csv files were found there at all.');
  }

  lines.push('  Expected <EventType>-YYYY-MM-DD.csv, or <EventType>/YYYY-MM-DD-<Id>.csv.');
  lines.push('  Download them with:');
  lines.push(`    sf audit events pull -o <org> --since 7 --output ${egress(dir)}`);
  return lines.join('\n') + '\n';
}

program
  .command('catalog')
  .description('list the detection rules this tool checks for')
  .option('--family <name>', 'show only one family (e.g. Log4Shell)')
  .option('--json', 'emit the rules as JSON')
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage catalog
  $ sfelf-triage catalog --family Log4Shell
  $ sfelf-triage catalog --json`,
  )
  .action((opts: { family?: string; json?: boolean }) => {
    const rules = loadCatalog();
    process.stdout.write(
      (opts.json ? renderCatalogJson(rules, opts.family) : renderCatalog(rules, opts.family)) + '\n',
    );
  });

program
  .command('explain')
  .description('explain what a verdict means and how it is decided')
  .argument('[verdict]', 'BENIGN_SCANNER | SUSPICIOUS | LIKELY_ABUSE (omit to explain all)')
  .option('--json', 'emit the verdict logic as JSON')
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage explain
  $ sfelf-triage explain LIKELY_ABUSE
  $ sfelf-triage explain --json`,
  )
  .action((verdict: string | undefined, opts: { json?: boolean }) => {
    process.stdout.write(
      (opts.json ? explainJson(verdict) : explainVerdict(verdict)) + '\n',
    );
    // An unrecognized verdict is a typo, and a typo that exits 0 reads as an answer.
    if (verdict !== undefined && !isVerdict(verdict.toUpperCase())) process.exitCode = 1;
  });

program
  .command('doctor')
  .description('check this installation: Node version, regex engine, resource ceilings')
  .option('--json', 'emit the diagnosis as JSON')
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage doctor
  $ sfelf-triage doctor --json

Exit codes:
  0  healthy
  2  degraded — the JS regex fallback is in use, or Node is out of the supported range`,
  )
  .action((opts: { json?: boolean }) => {
    const matcher = new SafeMatcher();
    const input = {
      nodeVersion: process.version,
      supportedRange: pkg.engines.node,
      engine: matcher.engine,
      degradedReason: matcher.degradedReason,
      limits: DEFAULT_LIMITS,
    };
    process.stdout.write((opts.json ? renderDoctorJson(input) : renderDoctor(input)) + '\n');
    // Same code --require-re2 uses, so one number means "this install cannot stand
    // behind its own guarantees" wherever it appears.
    if (doctorStatus(input) !== 'ok') process.exitCode = 2;
  });

program.addHelpText(
  'after',
  `
Commands at a glance:
  analyze [dir]      triage a directory (or one CSV) of EventLogFiles → per-IP verdicts
  catalog            list what the tool detects (Class 1 scanner probes, Class 2 SF abuse)
  explain [verdict]  what the verdicts mean and how they are decided
  doctor             check this installation and print the fix for anything degraded

catalog, explain and doctor all take --json, so a script or an agent can read the
tool's own coverage and logic rather than parse its prose.

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
