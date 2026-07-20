// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*[A-Za-z]/g;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f]/g;
const FORMULA_LEAD = /^[=+\-@\t\r]/;

/** The ONLY function that prepares an untrusted string for terminal/file output. */
export function egress(value: string): string {
  return value.replace(ANSI, '').replace(CONTROL, '');
}

/** egress + Excel/Sheets formula-injection guard for CSV/spreadsheet output. */
export function csvCell(value: string): string {
  const clean = egress(value);
  return FORMULA_LEAD.test(clean) ? `'${clean}` : clean;
}
