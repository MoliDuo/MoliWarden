import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import { readSetting, writeSetting } from '../../platform/db/settings';
import { columnOf, KIND_NAMES, RECORD_KINDS, type KindName, type Snapshot, type VaultRecord } from './archive';
import { emptyRuntime, type Runtime } from './settings';

export const SETTINGS_KEY = 'backup.settings';
const RUNTIME_KEY = 'backup.runtime';
// The settings a backup carries. The others are this server's own state
// (push registration, backup history).
export const BACKED_UP_SETTINGS = [SETTINGS_KEY, 'audit.retention', 'yubico.credentials'];
const INSERT_BATCH_ROWS = 500;

const fieldsOf = (kind: KindName) => Object.entries(RECORD_KINDS[kind].fields);

async function readKind(db: Executor, kind: KindName): Promise<VaultRecord[]> {
  const spec = RECORD_KINDS[kind];
  // Table and column names come from RECORD_KINDS, never from input.
  const columns = sql.join(fieldsOf(kind).map(([field]) => sql`${sql.ref(columnOf(field))} AS ${sql.ref(field)}`));
  const order = sql.join(spec.order.map((field) => sql.ref(columnOf(field))));
  let query = sql<VaultRecord>`SELECT ${columns} FROM ${sql.table(spec.table)}`;
  if (kind === 'settings') query = sql<VaultRecord>`${query} WHERE key = ANY(${BACKED_UP_SETTINGS})`;
  if (kind === 'attachments') query = sql<VaultRecord>`${query} WHERE uploaded_at IS NOT NULL`;
  const { rows } = await sql<VaultRecord>`${query} ORDER BY ${order}`.execute(db);
  return rows;
}

// Everything a backup holds. Run it in one snapshot (repeatable read).
export async function readSnapshot(db: Executor): Promise<Snapshot> {
  const snapshot = {} as Snapshot;
  for (const kind of KIND_NAMES) snapshot[kind] = await readKind(db, kind);
  return snapshot;
}

export async function hasVaultData(db: Executor): Promise<boolean> {
  const { rows } = await sql<{ found: boolean }>`
    SELECT EXISTS (SELECT 1 FROM ciphers) OR EXISTS (SELECT 1 FROM folders)
        OR EXISTS (SELECT 1 FROM attachments) OR EXISTS (SELECT 1 FROM sends) AS found
  `.execute(db);
  return !!rows[0]?.found;
}

// JSON fields are written as JSON text: pg would turn an array into a
// Postgres array.
function cell(type: string, value: unknown): unknown {
  return (type === 'json' || type === 'object') && value !== null ? JSON.stringify(value) : value;
}

// Replaces the accounts, vaults and backed-up settings with the snapshot.
// Everything that hangs off an account (sessions, devices, Sends) goes
// with it. Run it in a transaction.
export async function replaceInstance(db: Executor, snapshot: Snapshot): Promise<void> {
  await db.deleteFrom('users').execute();
  await db.deleteFrom('organizations').execute();
  await db.deleteFrom('settings').where('key', 'in', BACKED_UP_SETTINGS).execute();
  for (const kind of KIND_NAMES) {
    const records = kind === 'settings' ? snapshot.settings.filter((record) => BACKED_UP_SETTINGS.includes(String(record.key))) : snapshot[kind];
    const fields = fieldsOf(kind);
    const columns = sql.join(fields.map(([field]) => sql.ref(columnOf(field))));
    for (let i = 0; i < records.length; i += INSERT_BATCH_ROWS) {
      const values = records
        .slice(i, i + INSERT_BATCH_ROWS)
        .map((record) => sql`(${sql.join(fields.map(([field, type]) => cell(type, record[field])))})`);
      await sql`INSERT INTO ${sql.table(RECORD_KINDS[kind].table)} (${columns}) VALUES ${sql.join(values)}`.execute(db);
    }
  }
}

export async function listAttachmentKeys(db: Executor): Promise<Array<{ cipherId: string; id: string }>> {
  const rows = await db.selectFrom('attachments').select(['cipher_id', 'id']).execute();
  return rows.map((row) => ({ cipherId: row.cipher_id, id: row.id }));
}

// The settings, sealed (see settings-crypto.ts).
export function readStoredSettings(db: Executor): Promise<string | null> {
  return readSetting<string>(db, SETTINGS_KEY);
}

export function writeStoredSettings(db: Executor, sealed: string): Promise<void> {
  return writeSetting(db, SETTINGS_KEY, sealed);
}

export async function readRuntimes(db: Executor): Promise<Record<string, Runtime>> {
  const value = await readSetting<{ destinations?: Record<string, Partial<Runtime>> }>(db, RUNTIME_KEY);
  return Object.fromEntries(Object.entries(value?.destinations ?? {}).map(([id, runtime]) => [id, { ...emptyRuntime(), ...runtime }]));
}

// Merges `changes` into one destination's history. A single statement, so
// runs of different destinations never overwrite each other's history.
export async function updateRuntime(db: Executor, destinationId: string, changes: Partial<Runtime>): Promise<void> {
  const patch = JSON.stringify(changes);
  const initial = JSON.stringify({ destinations: { [destinationId]: { ...emptyRuntime(), ...changes } } });
  await sql`
    INSERT INTO settings (key, value) VALUES (${RUNTIME_KEY}, ${initial}::jsonb)
    ON CONFLICT (key) DO UPDATE SET value = jsonb_set(
      jsonb_set(settings.value, '{destinations}', COALESCE(settings.value -> 'destinations', '{}'::jsonb)),
      ARRAY['destinations', ${destinationId}::text],
      COALESCE(settings.value -> 'destinations' -> ${destinationId}::text, '{}'::jsonb) || ${patch}::jsonb
    )
  `.execute(db);
}
