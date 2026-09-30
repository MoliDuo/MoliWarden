import { randomUUID } from 'node:crypto';
import type { Executor } from './index';

// A named lock shared by every function instance: whoever holds the lease
// runs the job, everyone else backs off. A lease outlives its holder by at
// most `ttlMs`, so a crashed holder blocks nobody for long.

// The token to release the lease with, or null while someone else holds it.
export async function acquireLease(db: Executor, name: string, ttlMs: number, now = Date.now()): Promise<string | null> {
  const token = randomUUID();
  const expiresAt = new Date(now + ttlMs).toISOString();
  const row = await db
    .insertInto('job_leases')
    .values({ name, token, expires_at: expiresAt })
    .onConflict((oc) =>
      oc
        .column('name')
        .doUpdateSet({ token, expires_at: expiresAt })
        .where('job_leases.expires_at', '<=', new Date(now).toISOString()),
    )
    .returning('name')
    .executeTakeFirst();
  return row ? token : null;
}

export async function releaseLease(db: Executor, name: string, token: string): Promise<void> {
  await db.deleteFrom('job_leases').where('name', '=', name).where('token', '=', token).execute();
}

// Runs `job` under the lease; null if the lease is held elsewhere.
export async function withLease<T>(db: Executor, name: string, ttlMs: number, job: () => Promise<T>): Promise<{ value: T } | null> {
  const token = await acquireLease(db, name, ttlMs);
  if (!token) return null;
  try {
    return { value: await job() };
  } finally {
    await releaseLease(db, name, token).catch((error) => console.error('Releasing lease %s failed:', name, error));
  }
}
