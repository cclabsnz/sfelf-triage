import { createReadStream } from 'node:fs';
import { parse } from 'csv-parse';
import { ingress } from '../sanitizer/ingress.js';
import type { SafeEvent, RawRow } from '../types.js';
import type { LogFile } from './discover.js';

export async function* ingestFile(file: LogFile): AsyncGenerator<SafeEvent> {
  const parser = createReadStream(file.path).pipe(
    parse({
      columns: true,
      relax_quotes: true,
      relax_column_count: true,
      skip_records_with_error: true,
      bom: true,
    }),
  );
  for await (const row of parser) {
    yield ingress(row as RawRow, file.eventType);
  }
}
