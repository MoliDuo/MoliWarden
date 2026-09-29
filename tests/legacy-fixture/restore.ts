// Loads v1.sql, a plain pg_dump, with the pg driver alone (no psql needed):
// statements run as they are, the rows of each COPY block are inserted.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { FIXTURE_DIR } from './common';

const ESCAPES: Record<string, string> = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' };

// A field of COPY's text format.
function copyField(field: string): string | null {
  if (field === '\\N') return null;
  return field.replace(/\\(?:([0-7]{1,3})|x([0-9a-fA-F]{1,2})|(.))/g, (_, octal, hex, char) =>
    octal ? String.fromCharCode(parseInt(octal, 8)) : hex ? String.fromCharCode(parseInt(hex, 16)) : (ESCAPES[char] ?? char),
  );
}

export async function restoreLegacyDump(connectionString: string, dump = readFileSync(join(FIXTURE_DIR, 'v1.sql'), 'utf8')): Promise<void> {
  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    const lines = dump.split('\n');
    let statement: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const copy = /^COPY (\S+) \(([^)]*)\) FROM stdin;$/.exec(line);
      if (copy) {
        const columns = copy[2].split(', ');
        const placeholders = columns.map((_, n) => `$${n + 1}`).join(', ');
        for (i++; lines[i] !== '\\.'; i++) {
          await client.query(`INSERT INTO ${copy[1]} (${copy[2]}) VALUES (${placeholders})`, lines[i].split('\t').map(copyField));
        }
        continue;
      }
      if (!statement.length && (!line.trim() || line.startsWith('--'))) continue;
      statement.push(line);
      if (line.trimEnd().endsWith(';')) {
        await client.query(statement.join('\n'));
        statement = [];
      }
    }
  } finally {
    await client.end();
  }
}
