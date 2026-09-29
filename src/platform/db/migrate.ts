import { Kysely, PostgresAdapter, PostgresDialect, sql, type Transaction } from 'kysely';
import { Migrator, type Migration } from 'kysely/migration';
import type pg from 'pg';
import * as init from './migrations/0001_init';

// Schema changes are migrations, applied in order and recorded in
// kysely_migration. Within a release, a migration only adds: the version
// still running during a deployment must keep working on the new schema.

const MIGRATIONS: Record<string, Migration> = {
  '0001_init': init,
};
const LATEST = Object.keys(MIGRATIONS).at(-1)!;
const LOCK_ID = 7_302_914_551;

export type SchemaState = 'current' | 'outdated' | 'legacy';

// One cheap query: whether the latest migration is recorded, and whether
// the tables are those of the server before migrations existed.
export async function schemaState(db: Kysely<any>): Promise<SchemaState> {
  const { rows } = await sql<{ migrations: boolean; legacy: boolean }>`
    SELECT to_regclass('kysely_migration') IS NOT NULL AS migrations,
           to_regclass('config') IS NOT NULL AS legacy
  `.execute(db);
  const { migrations, legacy } = rows[0];
  if (!migrations) return legacy ? 'legacy' : 'outdated';
  const latest = await sql`SELECT 1 FROM kysely_migration WHERE name = ${LATEST}`.execute(db);
  return latest.rows.length ? 'current' : 'outdated';
}

// Kysely's own lock is a session-level advisory lock, which a transaction
// pooler (PgBouncer, Neon's pooled URL) can strand on a server connection
// when a migration fails. Migrations here run in one transaction that
// takes a transaction-level lock first instead.
class TransactionLockedAdapter extends PostgresAdapter {
  override async acquireMigrationLock(): Promise<void> {}
  override async releaseMigrationLock(): Promise<void> {}
}

class MigrationDialect extends PostgresDialect {
  override createAdapter() {
    return new TransactionLockedAdapter();
  }
}

// A handle for applyMigrations. Not to be destroyed: that would end the pool.
export const migrationDb = (pool: pg.Pool): Kysely<any> => new Kysely({ dialect: new MigrationDialect({ pool }) });

// Applies what is missing inside `trx`, which must come from migrationDb.
// Concurrent callers wait for the lock and then find nothing left to do.
export async function applyMigrations(trx: Transaction<any>): Promise<string[]> {
  await sql`SELECT pg_advisory_xact_lock(${LOCK_ID})`.execute(trx);
  const migrator = new Migrator({ db: trx, provider: { getMigrations: async () => MIGRATIONS } });
  const { error, results = [] } = await migrator.migrateToLatest();
  if (error) {
    const failed = results.find((result) => result.status === 'Error');
    throw new Error(failed ? `Migration ${failed.migrationName} failed: ${String(error)}` : String(error), { cause: error });
  }
  return results.map((result) => result.migrationName);
}

export function migrateToLatest(pool: pg.Pool): Promise<string[]> {
  return migrationDb(pool).transaction().execute(applyMigrations);
}
