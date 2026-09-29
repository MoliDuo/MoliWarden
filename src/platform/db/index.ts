import { Kysely, PostgresDialect, type Transaction } from 'kysely';
import pg from 'pg';
import type { Database } from './schema';

export type Db = Kysely<Database>;
// Repositories take either, so a service can run several of them in one transaction.
export type Executor = Kysely<Database> | Transaction<Database>;

const INT8 = 20;
const NUMERIC = 1700;
const TIMESTAMPTZ = 1184;
const parseTimestamp = pg.types.getTypeParser(TIMESTAMPTZ);

// How this pool reads values; the global pg defaults stay untouched.
// Counts and sizes stay far below 2^53, and times are ISO strings as the
// API sends them.
const types = {
  getTypeParser(oid: number, format?: 'text' | 'binary') {
    if (oid === INT8 || oid === NUMERIC) return (value: string) => Number(value);
    if (oid === TIMESTAMPTZ) return (value: string) => (parseTimestamp(value) as Date).toISOString();
    return pg.types.getTypeParser(oid, format);
  },
};

function sslFor(connectionString: string): pg.PoolConfig['ssl'] {
  const url = new URL(connectionString);
  const sslmode = url.searchParams.get('sslmode');
  if (sslmode === 'disable') return false;
  if (sslmode) return { rejectUnauthorized: sslmode === 'verify-full' || sslmode === 'verify-ca' };
  return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ? false : { rejectUnauthorized: false };
}

export function createPool(options: { connectionString: string; max?: number }): pg.Pool {
  const url = new URL(options.connectionString);
  // node-postgres would let these override the ssl setting below.
  url.searchParams.delete('sslmode');
  url.searchParams.delete('channel_binding');
  return new pg.Pool({
    connectionString: url.toString(),
    ssl: sslFor(options.connectionString),
    max: options.max ?? 5,
    idleTimeoutMillis: 5_000,
    connectionTimeoutMillis: 10_000,
    types,
  });
}

export function createDb(pool: pg.Pool): Db {
  return new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
}
