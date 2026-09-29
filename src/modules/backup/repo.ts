import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import { TABLE_NAMES, TABLES, type Snapshot, type TableName } from './archive';
import { emptyRuntime, type Runtime } from './settings';

export const SETTINGS_KEY = 'backup.settings.v1';
const RUNTIME_KEY = 'backup.runtime.v1';
// The server settings a backup carries. The rest of the config table is
// this server's own state (schema version, leases, push registration).
export const BACKED_UP_CONFIG = [
  SETTINGS_KEY,
  'audit.logs.settings.v1',
  'globalSettings__yubico__clientId',
  'globalSettings__yubico__key',
];
const INSERT_BATCH_ROWS = 500;

type Row = Record<string, unknown>;

// Rows in a stable order, so the same data gives the same archive.
const ORDER: Partial<Record<TableName, string[]>> = {
  config: ['key'],
  domain_settings: ['user_id'],
  user_revisions: ['user_id'],
  collection_members: ['collection_id', 'membership_id'],
  cipher_collections: ['cipher_id', 'collection_id'],
  cipher_user_state: ['cipher_id', 'user_id'],
  attachments: ['cipher_id', 'id'],
};

async function readTable(db: Executor, table: TableName): Promise<Row[]> {
  // The table names and columns come from TABLES, never from input.
  const columns = sql.join(TABLES[table].columns.map((column) => sql.ref(column)));
  const order = sql.join((ORDER[table] ?? ['created_at', 'id']).map((column) => sql.ref(column)));
  let query = sql<Row>`SELECT ${columns} FROM ${sql.table(table)}`;
  if (table === 'config') query = sql<Row>`${query} WHERE key = ANY(${BACKED_UP_CONFIG})`;
  const { rows } = await sql<Row>`${query} ORDER BY ${order}`.execute(db);
  return rows;
}

// Everything a backup holds, read in one snapshot.
export async function readSnapshot(db: Executor): Promise<Snapshot> {
  const snapshot = {} as Snapshot;
  for (const table of TABLE_NAMES) snapshot[table] = await readTable(db, table);
  return snapshot;
}

export async function hasVaultData(db: Executor): Promise<boolean> {
  const { rows } = await sql<{ found: boolean }>`
    SELECT EXISTS (SELECT 1 FROM ciphers) OR EXISTS (SELECT 1 FROM folders)
        OR EXISTS (SELECT 1 FROM attachments) OR EXISTS (SELECT 1 FROM sends) AS found
  `.execute(db);
  return !!rows[0]?.found;
}

// Replaces the accounts, vaults and backed-up settings with the snapshot.
// Everything that hangs off an account (sessions, devices, Sends) goes
// with it. Run it in a transaction.
export async function replaceInstance(db: Executor, snapshot: Snapshot): Promise<void> {
  await db.deleteFrom('users').execute();
  await db.deleteFrom('organizations').execute();
  await db.deleteFrom('config').where('key', 'in', BACKED_UP_CONFIG).execute();
  for (const table of TABLE_NAMES) {
    const rows = snapshot[table];
    const columns = TABLES[table].columns;
    for (let i = 0; i < rows.length; i += INSERT_BATCH_ROWS) {
      const values = rows
        .slice(i, i + INSERT_BATCH_ROWS)
        .map((row) => sql`(${sql.join(columns.map((column) => row[column] as unknown))})`);
      await sql`INSERT INTO ${sql.table(table)} (${sql.join(columns.map((column) => sql.ref(column)))}) VALUES ${sql.join(values)}`.execute(db);
    }
  }
}

export async function listAttachmentKeys(db: Executor): Promise<Array<{ cipherId: string; id: string }>> {
  const rows = await db.selectFrom('attachments').select(['cipher_id', 'id']).execute();
  return rows.map((row) => ({ cipherId: row.cipher_id, id: row.id }));
}

export async function readStoredSettings(db: Executor): Promise<string | null> {
  const row = await db.selectFrom('config').select('value').where('key', '=', SETTINGS_KEY).executeTakeFirst();
  return row?.value ?? null;
}

export async function writeStoredSettings(db: Executor, value: string): Promise<void> {
  await db
    .insertInto('config')
    .values({ key: SETTINGS_KEY, value })
    .onConflict((oc) => oc.column('key').doUpdateSet({ value }))
    .execute();
}

export async function readRuntimes(db: Executor): Promise<Record<string, Runtime>> {
  const row = await db.selectFrom('config').select('value').where('key', '=', RUNTIME_KEY).executeTakeFirst();
  try {
    const parsed = JSON.parse(row?.value ?? '{}') as { destinations?: Record<string, Partial<Runtime>> };
    return Object.fromEntries(
      Object.entries(parsed.destinations ?? {}).map(([id, runtime]) => [id, { ...emptyRuntime(), ...runtime }]),
    );
  } catch {
    return {};
  }
}

// Merges `changes` into one destination's history. A single statement, so
// runs of different destinations never overwrite each other's history.
export async function updateRuntime(db: Executor, destinationId: string, changes: Partial<Runtime>): Promise<void> {
  const patch = JSON.stringify(changes);
  const initial = JSON.stringify({ version: 1, destinations: { [destinationId]: { ...emptyRuntime(), ...changes } } });
  await sql`
    INSERT INTO config (key, value) VALUES (${RUNTIME_KEY}, ${initial})
    ON CONFLICT (key) DO UPDATE SET value = jsonb_set(
      jsonb_set(config.value::jsonb, '{destinations}', COALESCE(config.value::jsonb -> 'destinations', '{}'::jsonb)),
      ARRAY['destinations', ${destinationId}::text],
      COALESCE(config.value::jsonb -> 'destinations' -> ${destinationId}::text, '{}'::jsonb) || ${patch}::jsonb
    )::text
  `.execute(db);
}
