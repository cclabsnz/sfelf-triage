import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { parse } from 'csv-parse';
import { DEFAULT_LIMITS, LimitReport, type Limits } from '../limits.js';
import { ingress } from '../sanitizer/ingress.js';
import type { SafeEvent, RawRow } from '../types.js';
import type { LogFile } from './discover.js';

/**
 * Stream one CSV as sanitized events.
 *
 * `max_record_size` is the cap that matters for memory: `MAX_FIELD` in ingress clips a
 * field only *after* csv-parse has assembled it, so without a record ceiling a single
 * unterminated quote turns the remainder of the file into one buffered record and the
 * field cap never gets the chance to bound anything.
 *
 * The ceiling comes with a sharp edge that has to be handled rather than accepted:
 * csv-parse *ends the stream* at an oversized record. With `skip_records_with_error` it
 * does so without raising anything at all, so every row after the offending one just
 * disappears — one planted 20 MB field near the top of a log would silently retire the
 * rest of that file from the analysis. Byte accounting closes that hole: if the parser
 * consumed fewer bytes than the file holds, the read ended early and the run is recorded
 * as partial.
 */
export async function* ingestFile(
  file: LogFile,
  limits: Limits = DEFAULT_LIMITS,
  report: LimitReport = new LimitReport(),
): AsyncGenerator<SafeEvent> {
  const size = await stat(file.path)
    .then((s) => s.size)
    .catch(() => null);

  const parser = createReadStream(file.path).pipe(
    parse({
      columns: true,
      relax_quotes: true,
      relax_column_count: true,
      skip_records_with_error: true,
      max_record_size: limits.maxRecordSize,
      bom: true,
    }),
  );

  for await (const row of parser) {
    yield ingress(row as RawRow, file.eventType);
  }

  if (size != null && parser.info.bytes < size) {
    report.reached('maxRecordSize');
  }
}
