import type { Env } from '../types';

// In-process replacement for the Durable Object namespaces upstream used.
// Objects are instantiated per call; their persistent state lives in the
// `config` table under a namespaced key, and `acquireLease` gives callers an
// atomic cross-instance lock (Durable Objects were single-threaded, Vercel
// function instances are not).

export interface InProcessObjectStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<void>;
  // Stores `value` unless a record with a future `expiresAtMs` already exists.
  acquireLease<T extends { expiresAtMs: number }>(key: string, value: T, nowMs: number): Promise<boolean>;
}

export interface InProcessObjectState {
  storage: InProcessObjectStorage;
}

export interface InProcessObject {
  fetch(request: Request): Promise<Response>;
}

export interface InProcessObjectStub {
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
}

export interface InProcessObjectNamespace {
  idFromName(name: string): string;
  get(id: string): InProcessObjectStub;
}

function createStorage(db: D1Database, objectName: string): InProcessObjectStorage {
  const prefix = `object.${objectName}.`;
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const row = await db.prepare('SELECT value FROM config WHERE key = ?').bind(prefix + key).first<{ value: string }>();
      if (!row) return undefined;
      try {
        return JSON.parse(row.value) as T;
      } catch {
        return undefined;
      }
    },
    async put<T>(key: string, value: T): Promise<void> {
      await db
        .prepare('INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
        .bind(prefix + key, JSON.stringify(value))
        .run();
    },
    async delete(key: string): Promise<void> {
      await db.prepare('DELETE FROM config WHERE key = ?').bind(prefix + key).run();
    },
    async acquireLease<T extends { expiresAtMs: number }>(key: string, value: T, nowMs: number): Promise<boolean> {
      const row = await db
        .prepare(
          'INSERT INTO config(key, value) VALUES(?, ?) ' +
          'ON CONFLICT(key) DO UPDATE SET value = excluded.value ' +
          "WHERE COALESCE((config.value::jsonb ->> 'expiresAtMs')::bigint, 0) <= ? " +
          'RETURNING key'
        )
        .bind(prefix + key, JSON.stringify(value), nowMs)
        .first<{ key: string }>();
      return !!row;
    },
  };
}

export function createInProcessNamespace(
  env: () => Env,
  factory: (state: InProcessObjectState, env: Env) => InProcessObject
): InProcessObjectNamespace {
  return {
    idFromName(name: string): string {
      return name;
    },
    get(id: string): InProcessObjectStub {
      return {
        async fetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
          const currentEnv = env();
          const object = factory({ storage: createStorage(currentEnv.DB, id) }, currentEnv);
          const request = input instanceof Request ? input : new Request(String(input), init);
          return object.fetch(request);
        },
      };
    },
  };
}
