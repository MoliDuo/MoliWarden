// Minimal D1-compatible database interfaces.
//
// NodeWarden was written against Cloudflare D1. MoliWarden keeps the same
// query surface (prepare/bind/first/all/run/batch) and implements it on top of
// PostgreSQL in src/platform/pg-d1.ts, so the storage repositories stay close
// to upstream.

interface D1Meta {
  duration: number;
  changes: number;
  last_row_id: number | null;
  rows_read: number;
  rows_written: number;
  changed_db: boolean;
  size_after: number;
}

interface D1Result<T = Record<string, unknown>> {
  results: T[];
  success: true;
  meta: D1Meta;
}

interface D1ExecResult {
  count: number;
  duration: number;
}

interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(colName?: undefined): Promise<T | null>;
  first<T = unknown>(colName: string): Promise<T | null>;
  run<T = Record<string, unknown>>(): Promise<D1Result<T>>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
  raw<T = unknown[]>(): Promise<T[]>;
}

interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
  exec(query: string): Promise<D1ExecResult>;
}

// Cloudflare's runtime types allowed `response.json<T>()`; keep that ergonomic
// overload so upstream call sites compile unchanged.
interface Body {
  json<T = any>(): Promise<T>;
}
