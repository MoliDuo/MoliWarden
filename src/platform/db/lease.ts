import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { Executor } from './index';

// A named lock shared by every function instance: whoever holds the lease
// runs the job, everyone else backs off. A lease outlives its holder by at
// most `ttlMs`, so a crashed holder blocks nobody for long.

const keyOf = (name: string) => `lease.${name}`;

// The token to release the lease with, or null while someone else holds it.
export async function acquireLease(db: Executor, name: string, ttlMs: number, now = Date.now()): Promise<string | null> {
  const token = randomUUID();
  const value = JSON.stringify({ token, expiresAt: now + ttlMs });
  const row = await db
    .insertInto('config')
    .values({ key: keyOf(name), value })
    .onConflict((oc) =>
      oc
        .column('key')
        .doUpdateSet({ value })
        .where(sql<number>`COALESCE((config.value::jsonb ->> 'expiresAt')::bigint, 0)`, '<=', now),
    )
    .returning('key')
    .executeTakeFirst();
  return row ? token : null;
}

export async function releaseLease(db: Executor, name: string, token: string): Promise<void> {
  await db
    .deleteFrom('config')
    .where('key', '=', keyOf(name))
    .where(sql<string>`value::jsonb ->> 'token'`, '=', token)
    .execute();
}

// Runs `job` under the lease; null if the lease is held elsewhere.
export async function withLease<T>(db: Executor, name: string, ttlMs: number, job: () => Promise<T>): Promise<{ value: T } | null> {
  const token = await acquireLease(db, name, ttlMs);
  if (!token) return null;
  try {
    return { value: await job() };
  } finally {
    await releaseLease(db, name, token).catch((error) => console.error(`Releasing lease ${name} failed:`, error));
  }
}
