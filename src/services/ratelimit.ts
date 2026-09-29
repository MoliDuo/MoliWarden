import { LIMITS } from '../config/limits';

// Rate limiting service.
// - Login attempts: database-backed (low volume, security-critical).
// - API budgets and strict budgets: fixed windows in the UNLOGGED
//   rate_limit_buckets table (one upsert per request).

const CONFIG = {
  LOGIN_MAX_ATTEMPTS: LIMITS.rateLimit.loginMaxAttempts,
  LOGIN_LOCKOUT_MINUTES: LIMITS.rateLimit.loginLockoutMinutes,
  API_WINDOW_SECONDS: LIMITS.rateLimit.apiWindowSeconds,
};

export class RateLimitService {
  private static loginIpTableReady = false;
  private static strictBudgetTableReady = false;
  private static lastLoginIpCleanupAt = 0;
  private static lastStrictBudgetCleanupAt = 0;

  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.rateLimit.cleanupProbability;
  private static readonly LOGIN_IP_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;
  private static readonly LOGIN_IP_RETENTION_MS = LIMITS.rateLimit.loginIpRetentionMs;
  private static readonly STRICT_BUDGET_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;

  constructor(private db: D1Database) {}

  private shouldRunCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < RateLimitService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupLoginAttemptsIp(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastLoginIpCleanupAt, RateLimitService.LOGIN_IP_CLEANUP_INTERVAL_MS)) {
      return;
    }

    const cutoff = nowMs - RateLimitService.LOGIN_IP_RETENTION_MS;
    await this.db
      .prepare(
        'DELETE FROM login_attempts_ip WHERE updated_at < ? AND (locked_until IS NULL OR locked_until < ?)'
      )
      .bind(cutoff, nowMs)
      .run();
    RateLimitService.lastLoginIpCleanupAt = nowMs;
  }

  // Tables are created by ensureStorageSchema() (src/services/storage-schema.ts).
  private async ensureLoginIpTable(): Promise<void> {}

  private async ensureStrictBudgetTable(): Promise<void> {}

  private async maybeCleanupStrictBudgets(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastStrictBudgetCleanupAt, RateLimitService.STRICT_BUDGET_CLEANUP_INTERVAL_MS)) {
      return;
    }

    await this.db.prepare('DELETE FROM rate_limit_buckets WHERE expires_at < ?').bind(nowMs).run();
    RateLimitService.lastStrictBudgetCleanupAt = nowMs;
  }

  async checkLoginAttempt(ip: string): Promise<{
    allowed: boolean;
    remainingAttempts: number;
    retryAfterSeconds?: number;
  }> {
    await this.ensureLoginIpTable();

    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    const row = await this.db
      .prepare('SELECT attempts, locked_until FROM login_attempts_ip WHERE ip = ?')
      .bind(key)
      .first<{ attempts: number; locked_until: number | null }>();

    if (!row) {
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    if (row.locked_until && row.locked_until > now) {
      return {
        allowed: false,
        remainingAttempts: 0,
        retryAfterSeconds: Math.ceil((row.locked_until - now) / 1000),
      };
    }

    if (row.locked_until && row.locked_until <= now) {
      await this.db.prepare('DELETE FROM login_attempts_ip WHERE ip = ?').bind(key).run();
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    const remainingAttempts = Math.max(0, CONFIG.LOGIN_MAX_ATTEMPTS - (row.attempts || 0));
    return { allowed: true, remainingAttempts };
  }

  async recordFailedLogin(ip: string): Promise<{ locked: boolean; retryAfterSeconds?: number }> {
    await this.ensureLoginIpTable();

    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    // Single atomic UPSERT; concurrency-safe because the row is keyed by IP.
    const row = await this.db
      .prepare(
        'INSERT INTO login_attempts_ip(ip, attempts, locked_until, updated_at) VALUES(?, 1, NULL, ?) ' +
        'ON CONFLICT(ip) DO UPDATE SET attempts = login_attempts_ip.attempts + 1, updated_at = excluded.updated_at ' +
        'RETURNING attempts'
      )
      .bind(key, now)
      .first<{ attempts: number }>();

    const attempts = row?.attempts || 1;
    if (attempts >= CONFIG.LOGIN_MAX_ATTEMPTS) {
      const lockedUntil = now + CONFIG.LOGIN_LOCKOUT_MINUTES * 60 * 1000;
      await this.db
        .prepare('UPDATE login_attempts_ip SET locked_until = ?, updated_at = ? WHERE ip = ?')
        .bind(lockedUntil, now, key)
        .run();
      return { locked: true, retryAfterSeconds: CONFIG.LOGIN_LOCKOUT_MINUTES * 60 };
    }

    return { locked: false };
  }

  async clearLoginAttempts(ip: string): Promise<void> {
    await this.ensureLoginIpTable();
    const key = ip.trim() || 'unknown';
    await this.db.prepare('DELETE FROM login_attempts_ip WHERE ip = ?').bind(key).run();
  }

  private async incrementBucket(bucketKey: string, expiresAtMs: number, nowMs: number): Promise<number> {
    const row = await this.db
      .prepare(
        'INSERT INTO rate_limit_buckets(bucket_key, count, expires_at, updated_at) VALUES(?, 1, ?, ?) ' +
        'ON CONFLICT(bucket_key) DO UPDATE SET count = rate_limit_buckets.count + 1, updated_at = excluded.updated_at ' +
        'RETURNING count'
      )
      .bind(bucketKey, expiresAtMs, nowMs)
      .first<{ count: number }>();
    return Math.max(1, Number(row?.count || 1));
  }

  // Database-backed fixed-window rate limiter shared by all function instances.
  private async consumeFixedWindowBudget(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const windowStart = nowSec - (nowSec % windowSeconds);
    const windowEnd = windowStart + windowSeconds;
    const ttl = Math.max(1, windowEnd - nowSec);

    await this.maybeCleanupStrictBudgets(nowMs);
    const count = await this.incrementBucket(`fw:${identifier}:${windowStart}`, windowEnd * 1000, nowMs);
    if (count > maxRequests) {
      return { allowed: false, remaining: 0, retryAfterSeconds: ttl };
    }
    return { allowed: true, remaining: Math.max(0, maxRequests - count) };
  }

  async consumeStrictBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeStrictBudgetWithWindow(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  async consumeStrictBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    await this.ensureStrictBudgetTable();

    const key = String(identifier || '').trim() || 'unknown';
    const max = Math.max(1, Math.floor(maxRequests));
    const windowSize = Math.max(1, Math.floor(windowSeconds));
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const windowStart = nowSec - (nowSec % windowSize);
    const windowEndMs = (windowStart + windowSize) * 1000;
    const retryAfterSeconds = Math.max(1, Math.ceil((windowEndMs - nowMs) / 1000));
    const bucketKey = `${key}:${windowStart}`;

    await this.maybeCleanupStrictBudgets(nowMs);
    const count = await this.incrementBucket(bucketKey, windowEndMs, nowMs);
    if (count > max) {
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }
    return { allowed: true, remaining: Math.max(0, max - count) };
  }

  // General-purpose fixed-window budget.
  // Callers supply an identifier (must be unique per rate-limit category) and the
  // per-window maximum.  This single method replaces all previous specialised
  // budget helpers (write / sync / knownDevice / publicSend).
  async consumeBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  async consumeBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(identifier, maxRequests, windowSeconds);
  }
}

export { clientAddress as getClientIdentifier } from '../http/client';
