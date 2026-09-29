import { LIMITS } from '../../config/limits';
import { sha256Hex } from '../../platform/crypto';
import type { RateLimiter } from '../../platform/rate-limit';

// Guessing passwords, codes or keys locks the guesser out for a while after
// a run of failures. A success clears the count.

export interface Lockout {
  key: string;
  maxFailures: number;
  seconds: number;
}

const hashed = (kind: string, subject: string) => sha256Hex(`${kind}:${subject.trim() || 'unknown'}`);

// Failures from one client address at one thing guessed (an account, an
// API key, a Send), without keeping the thing itself: a few tries, then a
// short pause.
export function lockoutKey(address: string, kind: string, subject: string): Lockout {
  return {
    key: `${address}:login:${kind}:${hashed(kind, subject)}`,
    maxFailures: LIMITS.rateLimit.loginMaxAttempts,
    seconds: LIMITS.rateLimit.loginLockoutMinutes * 60,
  };
}

// Failures at one account from any address, which a guesser spreading over
// many addresses runs into: more tries, then a longer pause.
export function accountLockoutKey(kind: string, subject: string): Lockout {
  return {
    key: `account:login:${kind}:${hashed(kind, subject)}`,
    maxFailures: LIMITS.rateLimit.accountMaxAttempts,
    seconds: LIMITS.rateLimit.accountLockoutMinutes * 60,
  };
}

// Seconds until the lockout ends, or null.
export function lockedFor(limiter: RateLimiter, lockout: Lockout): Promise<number | null> {
  return limiter.lockedFor(lockout.key);
}

// Counts a failure. Returns the lockout in seconds when this one started it.
export function recordFailure(limiter: RateLimiter, lockout: Lockout): Promise<number | null> {
  return limiter.fail(lockout.key, lockout.maxFailures, lockout.seconds);
}

export function clearFailures(limiter: RateLimiter, lockout: Lockout): Promise<void> {
  return limiter.clearFailures(lockout.key);
}

export const minutes = (seconds: number) => Math.ceil(seconds / 60);
