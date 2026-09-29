import { sql } from 'kysely';
import type { Db } from './db';

// Counters shared by every function instance, kept in Postgres.

export interface RateLimiter {
  // Counts one request against `key` in a fixed window. Returns the seconds
  // until the window ends when the request is over `limit`, otherwise null.
  hit(key: string, limit: number, windowSeconds: number): Promise<number | null>;
  // Consecutive failures (wrong passwords, wrong send passwords) lock `key`
  // out for a while once they reach `maxFailures`.
  lockedFor(key: string): Promise<number | null>;
  fail(key: string, maxFailures: number, lockoutSeconds: number): Promise<number | null>;
  clearFailures(key: string): Promise<void>;
}

export function createRateLimiter(db: Db, now: () => number = Date.now): RateLimiter {
  return {
    async hit(key, limit, windowSeconds) {
      const nowMs = now();
      const windowStart = Math.floor(nowMs / 1000 / windowSeconds) * windowSeconds;
      const windowEndMs = (windowStart + windowSeconds) * 1000;
      const row = await db
        .insertInto('rate_limits')
        .values({ key: `${key}:${windowStart}`, count: 1, expires_at: new Date(windowEndMs).toISOString() })
        .onConflict((oc) => oc.column('key').doUpdateSet({ count: sql`rate_limits.count + 1` }))
        .returning('count')
        .executeTakeFirstOrThrow();
      return row.count > limit ? Math.max(1, Math.ceil((windowEndMs - nowMs) / 1000)) : null;
    },

    async lockedFor(key) {
      const nowMs = now();
      const row = await db.selectFrom('login_failures').select('locked_until').where('key', '=', key).executeTakeFirst();
      const until = row?.locked_until ? Date.parse(row.locked_until) : 0;
      return until > nowMs ? Math.ceil((until - nowMs) / 1000) : null;
    },

    async fail(key, maxFailures, lockoutSeconds) {
      const nowIso = new Date(now()).toISOString();
      const lockedUntil = new Date(now() + lockoutSeconds * 1000).toISOString();
      // Counting starts over once a lockout has run out.
      const next = sql<number>`CASE WHEN login_failures.locked_until <= ${nowIso}::timestamptz THEN 1 ELSE login_failures.failures + 1 END`;
      const row = await db
        .insertInto('login_failures')
        .values({ key, failures: 1, locked_until: maxFailures <= 1 ? lockedUntil : null, updated_at: nowIso })
        .onConflict((oc) =>
          oc.column('key').doUpdateSet({
            failures: next,
            locked_until: sql`CASE WHEN ${next} >= ${maxFailures} THEN ${lockedUntil}::timestamptz
              WHEN login_failures.locked_until <= ${nowIso}::timestamptz THEN NULL
              ELSE login_failures.locked_until END`,
            updated_at: nowIso,
          }),
        )
        .returning('failures')
        .executeTakeFirstOrThrow();
      return row.failures >= maxFailures ? lockoutSeconds : null;
    },

    async clearFailures(key) {
      await db.deleteFrom('login_failures').where('key', '=', key).execute();
    },
  };
}
