// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/g;
const FORMULA_LEAD = /^[=+\-@\t\r]/;
/** Characters that carry structural meaning inside a GFM table cell. */
const MD_STRUCTURAL = /[|\\]/g;

/** The ONLY function that prepares an untrusted string for terminal/file output. */
export function egress(value: string): string {
  return value.replace(ANSI, '').replace(CONTROL, '');
}

/** egress + Excel/Sheets formula-injection guard for CSV/spreadsheet output. */
export function csvCell(value: string): string {
  const clean = egress(value);
  return FORMULA_LEAD.test(clean) ? `'${clean}` : clean;
}

/**
 * egress + escaping for a GitHub-Flavored-Markdown table cell.
 *
 * `egress` removes control characters but leaves `|`, which is the column delimiter:
 * an unescaped pipe inside a value silently splits one cell into two and shifts every
 * later column, so a crafted field can forge or hide values in an incident write-up
 * that a reader takes as a faithful record. Pipes and backslashes are escaped in one
 * pass, so a backslash already present in the value becomes `\\` and cannot pair with
 * the escape emitted for a pipe that follows it.
 */
export function mdCell(value: string): string {
  return egress(value).replace(MD_STRUCTURAL, (c) => `\\${c}`);
}
