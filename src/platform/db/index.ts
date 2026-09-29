import { Kysely, PostgresDialect, type Transaction } from 'kysely';
import type pg from 'pg';
import type { Database } from './schema';

export type Db = Kysely<Database>;
// Repositories take either, so a service can run several of them in one transaction.
export type Executor = Kysely<Database> | Transaction<Database>;

export function createDb(pool: pg.Pool): Db {
  return new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
}
