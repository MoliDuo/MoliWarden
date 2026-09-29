import { sql, type Transaction } from 'kysely';
import type pg from 'pg';
import type { SecretBox } from '../../src/platform/crypto';
import type { Executor } from '../../src/platform/db';
import { applyMigrations, lockSchema, migrationDb } from '../../src/platform/db/migrate';
import type { Database } from '../../src/platform/db/schema';
import { readSetting, writeSetting } from '../../src/platform/db/settings';
import { sealApiKey } from '../../src/modules/auth/api-key';
import { openSettings, sealSettings } from '../../src/modules/backup/settings-crypto';
import { createRemoteFetch } from '../../src/modules/backup/endpoint';
import { openRemoteStore } from '../../src/modules/backup/remote';
import { readStoredSettings, replaceInstance, writeStoredSettings } from '../../src/modules/backup/repo';
import { INDEX_PATH } from '../../src/modules/backup/runs';
import { sealSnapshotSecrets } from '../../src/modules/backup/secrets';
import { parseStoredSettings } from '../../src/modules/backup/settings';
import { findCiphers } from '../../src/modules/ciphers/repo';
import { saveInstallation } from '../../src/modules/push/repo';
import { sealInstallationKey } from '../../src/modules/push/service';
import { convertDatabase, LEGACY_TABLES, type LegacyTables, type Report } from './transform';

// Moves a database of the old backend onto today's schema, in one
// transaction:
//   1. the old tables move, untouched, into the schema `legacy`;
//   2. the migrations create today's tables in `public`;
//   3. the old rows are converted (transform.ts) and written;
//   4. the result is checked, and the migration recorded.
// A failure anywhere leaves the database as it was. `rollbackLegacy` puts
// the old tables back while nothing has been written since.

const LEGACY_SCHEMA = 'legacy';
const MARKER = 'legacy.migration';
const INSERT_BATCH_ROWS = 500;
const OLD_INDEX_PATH = 'attachments/.nodewarden-attachment-index.v1.json';

export interface MigrationResult {
  status: 'migrated' | 'dry-run';
  // Rows read per old table, and written per new one.
  read: Record<string, number>;
  written: Record<string, number>;
  report: Report;
}

export class MigrationError extends Error {}

class DryRun extends Error {
  constructor(readonly result: MigrationResult) {
    super('dry run');
  }
}

type Trx = Transaction<any>;
const executor = (trx: Trx) => trx as unknown as Executor;

async function publicTables(trx: Trx, schema = 'public'): Promise<string[]> {
  const { rows } = await sql<{ name: string }>`SELECT tablename AS name FROM pg_tables WHERE schemaname = ${schema} ORDER BY tablename`.execute(trx);
  return rows.map((row) => row.name);
}

async function exists(trx: Trx, relation: string): Promise<boolean> {
  const { rows } = await sql<{ found: boolean }>`SELECT to_regclass(${relation}) IS NOT NULL AS found`.execute(trx);
  return rows[0].found;
}

async function schemaExists(trx: Trx, schema: string): Promise<boolean> {
  const { rows } = await sql<{ found: boolean }>`SELECT to_regnamespace(${schema}) IS NOT NULL AS found`.execute(trx);
  return rows[0].found;
}

// What rollback compares: whether anything was written since the migration.
// Sessions are left out; clients refresh them on their own.
const WATCHED: Array<[keyof Database, string | null]> = [
  ['users', 'revision_date'], ['two_factor_providers', null], ['webauthn_credentials', 'updated_at'], ['folders', 'updated_at'],
  ['organizations', 'updated_at'], ['memberships', 'updated_at'], ['collections', 'updated_at'], ['collection_grants', null],
  ['ciphers', 'updated_at'], ['cipher_collections', null], ['cipher_user_state', null], ['attachments', 'created_at'],
  ['sends', 'updated_at'], ['devices', 'updated_at'], ['invites', 'updated_at'], ['settings', null],
];

async function fingerprint(trx: Trx): Promise<string> {
  const parts: string[] = [];
  for (const [table, column] of WATCHED) {
    const latest = column ? sql`max(${sql.ref(column)})::text` : sql`NULL`;
    // The marker itself, backup history and the push relay registration are
    // the server's own bookkeeping.
    const where = table === 'settings' ? sql`WHERE key NOT IN (${MARKER}, 'backup.runtime', 'push.installation')` : sql``;
    const { rows } = await sql<{ n: number; latest: string | null }>`SELECT count(*)::int AS n, ${latest} AS latest FROM ${sql.table(table)} ${where}`.execute(trx);
    parts.push(`${table}:${rows[0].n}:${rows[0].latest ?? ''}`);
  }
  return parts.join('|');
}

async function insertAll<T extends keyof Database>(trx: Trx, table: T, rows: object[]): Promise<void> {
  for (let i = 0; i < rows.length; i += INSERT_BATCH_ROWS) {
    await trx.insertInto(table).values(rows.slice(i, i + INSERT_BATCH_ROWS)).execute();
  }
}

async function countRows(trx: Trx, table: keyof Database): Promise<number> {
  const { rows } = await sql<{ n: number }>`SELECT count(*)::int AS n FROM ${sql.table(table)}`.execute(trx);
  return rows[0].n;
}

async function readLegacyTables(trx: Trx, present: string[]): Promise<LegacyTables> {
  const tables: LegacyTables = {};
  for (const table of LEGACY_TABLES) {
    if (!present.includes(table)) continue;
    const { rows } = await sql<Record<string, unknown>>`SELECT * FROM ${sql.table(`${LEGACY_SCHEMA}.${table}`)}`.execute(trx);
    tables[table] = rows;
  }
  return tables;
}

async function migrate(trx: Trx, options: { secrets: SecretBox; jwtSecret: string }): Promise<MigrationResult> {
  await lockSchema(trx);
  if (await exists(trx, 'public.settings')) {
    const marker = await readSetting(executor(trx), MARKER);
    throw new MigrationError(marker ? 'The database was migrated already.' : 'The database holds no data of the earlier version.');
  }
  if (!(await exists(trx, 'public.config'))) throw new MigrationError('The database holds no data of the earlier version.');
  if (await schemaExists(trx, LEGACY_SCHEMA)) throw new MigrationError(`A schema named "${LEGACY_SCHEMA}" exists already; move it out of the way first.`);

  const present = await publicTables(trx);
  await sql`CREATE SCHEMA ${sql.id(LEGACY_SCHEMA)}`.execute(trx);
  for (const table of present) await sql`ALTER TABLE ${sql.table(`public.${table}`)} SET SCHEMA ${sql.id(LEGACY_SCHEMA)}`.execute(trx);
  await applyMigrations(trx);

  const tables = await readLegacyTables(trx, present);
  const converted = await convertDatabase(tables, { jwtSecret: options.jwtSecret });
  const { secrets } = options;
  const db = executor(trx);

  await replaceInstance(db, sealSnapshotSecrets(converted.snapshot, secrets));
  for (const { userId, key } of converted.apiKeys) {
    await trx.updateTable('users').set({ api_key: sealApiKey(secrets, userId, key) }).where('id', '=', userId).execute();
  }
  await insertAll(trx, 'devices', converted.devices);
  await insertAll(trx, 'refresh_tokens', converted.refreshTokens);
  await insertAll(trx, 'two_factor_remember_tokens', converted.rememberTokens);
  await insertAll(trx, 'sends', converted.sends);
  await insertAll(trx, 'invites', converted.invites);
  await insertAll(trx, 'audit_logs', converted.auditLogs);
  if (converted.pushInstallation) {
    const { id, key } = converted.pushInstallation;
    await saveInstallation(db, { id, key: sealInstallationKey(secrets, key) });
  }
  if (converted.backupRuntime) await writeSetting(db, 'backup.runtime', converted.backupRuntime);
  if (converted.backupSettings) {
    const users = converted.snapshot.users.map((user) => ({
      id: String(user.id),
      role: user.role as 'admin' | 'user',
      status: user.status as 'active' | 'banned',
      publicKey: user.publicKey as string | null,
    }));
    await writeStoredSettings(db, sealSettings(converted.backupSettings, secrets, users));
  }

  // Everything converted is there, and every cipher reads back.
  const { snapshot } = converted;
  const expected: Partial<Record<keyof Database, number>> = {
    users: snapshot.users.length,
    two_factor_providers: snapshot.twoFactorProviders.length,
    webauthn_credentials: snapshot.passkeys.length,
    folders: snapshot.folders.length,
    organizations: snapshot.organizations.length,
    memberships: snapshot.memberships.length,
    collections: snapshot.collections.length,
    collection_grants: snapshot.collectionGrants.length,
    ciphers: snapshot.ciphers.length,
    cipher_collections: snapshot.cipherCollections.length,
    cipher_user_state: snapshot.cipherStates.length,
    attachments: snapshot.attachments.length,
    devices: converted.devices.length,
    refresh_tokens: converted.refreshTokens.length,
    two_factor_remember_tokens: converted.rememberTokens.length,
    sends: converted.sends.length,
    invites: converted.invites.length,
    audit_logs: converted.auditLogs.length,
  };
  const written: Record<string, number> = {};
  for (const [table, count] of Object.entries(expected) as Array<[keyof Database, number]>) {
    written[table] = await countRows(trx, table);
    if (written[table] !== count) throw new MigrationError(`${table}: ${count} rows converted but ${written[table]} written.`);
  }
  const ciphers = await findCiphers(db, snapshot.ciphers.map((cipher) => String(cipher.id)));
  const names = new Map(snapshot.ciphers.map((cipher) => [cipher.id, (cipher.data as { name?: string }).name]));
  for (const cipher of ciphers) {
    if ((cipher.name ?? undefined) !== names.get(cipher.id)) throw new MigrationError(`Cipher ${cipher.id} does not read back as written.`);
  }
  if (ciphers.length !== snapshot.ciphers.length) throw new MigrationError('Some ciphers do not read back.');

  await writeSetting(db, MARKER, { migratedAt: new Date().toISOString(), fingerprint: await fingerprint(trx) });
  const read = Object.fromEntries(Object.entries(tables).map(([table, rows]) => [table, rows?.length ?? 0]));
  return { status: 'migrated', read, written, report: converted.report };
}

// `dryRun` does all of it and then rolls back.
export async function migrateLegacy(
  pool: pg.Pool,
  options: { secrets: SecretBox; jwtSecret: string; dryRun?: boolean },
): Promise<MigrationResult> {
  try {
    return await migrationDb(pool)
      .transaction()
      .execute(async (trx) => {
        const result = await migrate(trx, options);
        if (options.dryRun) throw new DryRun({ ...result, status: 'dry-run' });
        return result;
      });
  } catch (error) {
    if (error instanceof DryRun) return error.result;
    throw error;
  }
}

// Puts the old tables back, as long as nothing has been written since the
// migration: otherwise that would be lost.
export async function rollbackLegacy(pool: pg.Pool): Promise<void> {
  await migrationDb(pool)
    .transaction()
    .execute(async (trx) => {
      await lockSchema(trx);
      const marker = (await exists(trx, 'public.settings'))
        ? await readSetting<{ fingerprint: string }>(executor(trx), MARKER)
        : null;
      if (!marker || !(await schemaExists(trx, LEGACY_SCHEMA))) throw new MigrationError('There is no migration to roll back.');
      if ((await fingerprint(trx)) !== marker.fingerprint) {
        throw new MigrationError('Data was written since the migration and would be lost. Restore the snapshot taken before it instead.');
      }
      for (const table of await publicTables(trx)) await sql`DROP TABLE ${sql.table(`public.${table}`)} CASCADE`.execute(trx);
      for (const table of await publicTables(trx, LEGACY_SCHEMA)) {
        await sql`ALTER TABLE ${sql.table(`${LEGACY_SCHEMA}.${table}`)} SET SCHEMA public`.execute(trx);
      }
      await sql`DROP SCHEMA ${sql.id(LEGACY_SCHEMA)}`.execute(trx);
    });
}

// Remote backup destinations keep an index of the attachment files they
// have, which was renamed. Copying it spares the first backup from
// uploading every file again.
export async function migrateRemoteIndexes(
  db: Executor,
  secrets: SecretBox,
  allowPrivate: boolean,
): Promise<Array<{ destination: string; outcome: string }>> {
  const raw = await readStoredSettings(db);
  const plaintext = raw ? openSettings(raw, secrets) : null;
  if (!plaintext) return [];
  const results: Array<{ destination: string; outcome: string }> = [];
  for (const destination of parseStoredSettings(plaintext).destinations) {
    const store = openRemoteStore(destination, createRemoteFetch(allowPrivate), allowPrivate);
    try {
      const old = await store.get(OLD_INDEX_PATH);
      if (!old) results.push({ destination: destination.name, outcome: 'no index to copy' });
      else if (await store.get(INDEX_PATH)) results.push({ destination: destination.name, outcome: 'already copied' });
      else {
        await store.put(INDEX_PATH, old, 'application/json; charset=utf-8');
        results.push({ destination: destination.name, outcome: 'copied' });
      }
    } catch (error) {
      results.push({ destination: destination.name, outcome: `failed: ${error instanceof Error ? error.message : String(error)}` });
    }
  }
  return results;
}
