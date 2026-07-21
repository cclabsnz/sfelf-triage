#!/usr/bin/env node
import { createRequire } from 'node:module';
import { Command } from 'commander';
import { analyze } from './core/analyze.js';
import { discover } from './core/discover.js';
import { loadCatalog } from './catalog/index.js';
import { renderJson, renderTable, renderMarkdown } from './report/render.js';
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
  .addHelpText(
    'after',
    `
Examples:
  $ sfelf-triage analyze ./logs                 # table (default)
  $ sfelf-triage analyze ./logs --json          # JSON for pipelines
  $ sfelf-triage analyze ./logs --md            # markdown for an incident record

Get the logs first with:
  $ sf audit events pull -o <org> --since 7 --output ./logs

Exit codes: 0 = analysis ran; 1 = error (missing/unreadable dir, no CSVs).`,
  )
  .action(async (dir: string, opts: { json?: boolean; md?: boolean }) => {
    const files = await discover(dir).catch(() => []);
    if (files.length === 0) {
      process.stderr.write(
        `sfelf-triage: no EventLogFile CSVs found in "${dir}".\n` +
          'Files must be named like "Sites-2024-01-15.csv". Download them with:\n' +
          `  sf audit events pull -o <org> --since 7 --output ${dir}\n`,
      );
      process.exit(1);
    }
    const verdicts = await analyze(dir);
    if (opts.json) {
      process.stdout.write(renderJson(verdicts) + '\n');
    } else if (opts.md) {
      process.stdout.write(renderMarkdown(verdicts) + '\n');
    } else if (verdicts.length === 0) {
      process.stdout.write('No flagged IPs — no traffic in these logs matched the catalog.\n');
    } else {
      process.stdout.write(renderTable(verdicts) + '\n');
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
