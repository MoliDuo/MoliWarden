import { LIMITS } from '../../config/limits';
import { sha256Hex } from '../../platform/crypto';
import type { RateLimiter } from '../../platform/rate-limit';

// Guessing passwords, codes or keys locks the guesser out for a while after
// a run of failures. A success clears the count.

const MAX_FAILURES = LIMITS.rateLimit.loginMaxAttempts;
const LOCKOUT_SECONDS = LIMITS.rateLimit.loginLockoutMinutes * 60;

// Failures count per client address and per thing guessed (an account, an
// API key), without keeping the thing itself.
export function lockoutKey(address: string, kind: string, subject: string): string {
  return `${address}:login:${kind}:${sha256Hex(`${kind}:${subject.trim() || 'unknown'}`)}`;
}

// Seconds until the lockout ends, or null.
export function lockedFor(limiter: RateLimiter, key: string): Promise<number | null> {
  return limiter.lockedFor(key);
}

// Counts a failure. Returns the lockout in seconds when this one started it.
export function recordFailure(limiter: RateLimiter, key: string): Promise<number | null> {
  return limiter.fail(key, MAX_FAILURES, LOCKOUT_SECONDS);
}

export function clearFailures(limiter: RateLimiter, key: string): Promise<void> {
  return limiter.clearFailures(key);
}

export const minutes = (seconds: number) => Math.ceil(seconds / 60);
