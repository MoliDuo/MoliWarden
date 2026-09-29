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
        .insertInto('rate_limit_buckets')
        .values({ bucket_key: `${key}:${windowStart}`, count: 1, expires_at: windowEndMs, updated_at: nowMs })
        .onConflict((oc) =>
          oc.column('bucket_key').doUpdateSet({ count: sql`rate_limit_buckets.count + 1`, updated_at: nowMs }),
        )
        .returning('count')
        .executeTakeFirstOrThrow();
      return row.count > limit ? Math.max(1, Math.ceil((windowEndMs - nowMs) / 1000)) : null;
    },

    async lockedFor(key) {
      const nowMs = now();
      const row = await db
        .selectFrom('login_attempts_ip')
        .select('locked_until')
        .where('ip', '=', key)
        .executeTakeFirst();
      const until = row?.locked_until ?? 0;
      return until > nowMs ? Math.ceil((until - nowMs) / 1000) : null;
    },

    async fail(key, maxFailures, lockoutSeconds) {
      const nowMs = now();
      const lockedUntil = nowMs + lockoutSeconds * 1000;
      // Counting starts over once a lockout has run out.
      const next = sql<number>`CASE WHEN login_attempts_ip.locked_until <= ${nowMs}::bigint THEN 1 ELSE login_attempts_ip.attempts + 1 END`;
      const row = await db
        .insertInto('login_attempts_ip')
        .values({ ip: key, attempts: 1, locked_until: maxFailures <= 1 ? lockedUntil : null, updated_at: nowMs })
        .onConflict((oc) =>
          oc.column('ip').doUpdateSet({
            attempts: next,
            locked_until: sql`CASE WHEN ${next} >= ${maxFailures} THEN ${lockedUntil}::bigint
              WHEN login_attempts_ip.locked_until <= ${nowMs}::bigint THEN NULL
              ELSE login_attempts_ip.locked_until END`,
            updated_at: nowMs,
          }),
        )
        .returning('attempts')
        .executeTakeFirstOrThrow();
      return row.attempts >= maxFailures ? lockoutSeconds : null;
    },

    async clearFailures(key) {
      await db.deleteFrom('login_attempts_ip').where('ip', '=', key).execute();
    },
  };
}
