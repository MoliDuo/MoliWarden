import pg from 'pg';

// D1-compatible facade over node-postgres.
//
// Repositories keep writing SQLite-style `?` placeholders; they are rewritten
// to `$1..$n` here. Everything else (SQL dialect) must already be valid
// PostgreSQL. `batch()` runs inside a single transaction, matching D1's
// all-or-nothing batch semantics.

const { Pool, types } = pg;

// int8 (COUNT(*), BIGINT columns) and numeric (SUM) come back as strings by
// default. The codebase stores millisecond timestamps and counters that fit in
// a double, so parse them as numbers like D1 did.
types.setTypeParser(20, (value) => (value === null ? null : Number(value)));
types.setTypeParser(1700, (value) => (value === null ? null : Number(value)));

type Queryable = Pick<pg.Pool, 'query'> | pg.PoolClient;

const placeholderCache = new Map<string, string>();

export function rewritePlaceholders(sql: string): string {
  const cached = placeholderCache.get(sql);
  if (cached !== undefined) return cached;

  let out = '';
  let index = 0;
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    if (ch === '\'' || ch === '"') {
      // Copy quoted literal / identifier verbatim (doubled quote = escape).
      let j = i + 1;
      while (j < n) {
        if (sql[j] === ch) {
          if (sql[j + 1] === ch) {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      out += sql.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (ch === '-' && sql[i + 1] === '-') {
      const end = sql.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out += sql.slice(i, stop);
      i = stop;
      continue;
    }
    if (ch === '?') {
      index++;
      out += `$${index}`;
      i++;
      continue;
    }
    out += ch;
    i++;
  }

  if (placeholderCache.size > 2000) placeholderCache.clear();
  placeholderCache.set(sql, out);
  return out;
}

function normalizeParam(value: unknown): unknown {
  if (value === undefined) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (ArrayBuffer.isView(value) && !(value instanceof Buffer)) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  return value;
}

function buildMeta(rowCount: number | null, duration: number, isRead: boolean): D1Meta {
  const changes = isRead ? 0 : Math.max(0, rowCount || 0);
  return {
    duration,
    changes,
    last_row_id: null,
    rows_read: isRead ? Math.max(0, rowCount || 0) : 0,
    rows_written: changes,
    changed_db: changes > 0,
    size_after: 0,
  };
}

function toD1Result<T>(result: pg.QueryResult, duration: number): D1Result<T> {
  const isRead = result.command === 'SELECT';
  return {
    results: (result.rows || []) as T[],
    success: true,
    meta: buildMeta(result.rowCount, duration, isRead),
  };
}

export class PgPreparedStatement implements D1PreparedStatement {
  constructor(
    private readonly db: PgD1Database,
    readonly sql: string,
    readonly params: unknown[] = []
  ) {}

  bind(...values: unknown[]): D1PreparedStatement {
    return new PgPreparedStatement(this.db, this.sql, values.map(normalizeParam));
  }

  async execute(client?: Queryable): Promise<pg.QueryResult> {
    return this.db.query(this.sql, this.params, client);
  }

  async first<T = unknown>(colName?: string): Promise<T | null> {
    const result = await this.execute();
    const row = result.rows?.[0];
    if (!row) return null;
    if (colName !== undefined) {
      return (row[colName] ?? null) as T;
    }
    return row as T;
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const started = Date.now();
    const result = await this.execute();
    return toD1Result<T>(result, Date.now() - started);
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.run<T>();
  }

  async raw<T = unknown[]>(): Promise<T[]> {
    const result = await this.execute();
    const fields = result.fields.map((field) => field.name);
    return result.rows.map((row) => fields.map((name) => row[name]) as T);
  }
}

export class PgD1Database implements D1Database {
  constructor(readonly pool: pg.Pool) {}

  prepare(query: string): D1PreparedStatement {
    return new PgPreparedStatement(this, query);
  }

  async query(sql: string, params: unknown[], client?: Queryable): Promise<pg.QueryResult> {
    const target = client || this.pool;
    try {
      return await target.query(rewritePlaceholders(sql), params);
    } catch (error) {
      if (process.env.MOLIWARDEN_SQL_DEBUG === '1') {
        console.error('[sql error]', (error as Error).message, '\n', sql, params);
      }
      throw error;
    }
  }

  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    if (!statements.length) return [];
    return this.transaction(async (client) => {
      const results: D1Result<T>[] = [];
      for (const statement of statements) {
        const started = Date.now();
        const result = await (statement as PgPreparedStatement).execute(client);
        results.push(toD1Result<T>(result, Date.now() - started));
      }
      return results;
    });
  }

  async transaction<R>(fn: (client: pg.PoolClient) => Promise<R>): Promise<R> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const value = await fn(client);
      await client.query('COMMIT');
      return value;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async exec(query: string): Promise<D1ExecResult> {
    const started = Date.now();
    const result = await this.pool.query(query);
    const count = Array.isArray(result) ? result.length : 1;
    return { count, duration: Date.now() - started };
  }
}

export interface PgPoolOptions {
  connectionString: string;
  max?: number;
}

function shouldUseSsl(connectionString: string): boolean | { rejectUnauthorized: boolean } {
  try {
    const url = new URL(connectionString);
    const sslmode = url.searchParams.get('sslmode');
    if (sslmode === 'disable') return false;
    if (sslmode) return { rejectUnauthorized: sslmode === 'verify-full' || sslmode === 'verify-ca' };
    const host = url.hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' ? false : { rejectUnauthorized: false };
  } catch {
    return false;
  }
}

export function createPgPool(options: PgPoolOptions): pg.Pool {
  const connectionString = options.connectionString;
  const url = new URL(connectionString);
  // node-postgres parses sslmode itself and would override our ssl object.
  url.searchParams.delete('sslmode');
  url.searchParams.delete('channel_binding');
  return new Pool({
    connectionString: url.toString(),
    ssl: shouldUseSsl(connectionString),
    max: options.max ?? 5,
    idleTimeoutMillis: 5_000,
    connectionTimeoutMillis: 10_000,
  });
}
