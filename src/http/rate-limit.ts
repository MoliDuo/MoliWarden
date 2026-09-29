import type { MiddlewareHandler } from 'hono';
import type { RateLimiter } from '../platform/rate-limit';
import { clientAddress } from './client';
import { forbidden, tooManyRequests } from './errors';

// Every route declares the budget it draws from. Public routes count per
// client address, signed-in routes per user.
export const RATE_POLICIES = {
  // Signed-in API calls.
  api: { limit: 200, windowSeconds: 60 },
  // Imports and attachment uploads, which send one request per item.
  bulk: { limit: 1000, windowSeconds: 60 },
  // Public routes.
  public: { limit: 60, windowSeconds: 60 },
  'public-read': { limit: 120, windowSeconds: 60 },
  icons: { limit: 500, windowSeconds: 60 },
  sensitive: { limit: 30, windowSeconds: 60 },
  // Token refreshes, per session and per client address.
  'refresh-session': { limit: 30, windowSeconds: 60 },
  refresh: { limit: 300, windowSeconds: 60 },
  register: { limit: 5, windowSeconds: 60 },
  // Password hints, which tell something about a password to whoever knows the email.
  'password-hint': { limit: 1, windowSeconds: 60 },
  'password-hint-hourly': { limit: 3, windowSeconds: 3600 },
} as const satisfies Record<string, { limit: number; windowSeconds: number }>;

export type RatePolicy = keyof typeof RATE_POLICIES;

export async function consume(limiter: RateLimiter, policy: RatePolicy, subject: string): Promise<void> {
  const { limit, windowSeconds } = RATE_POLICIES[policy];
  const retryAfter = await limiter.hit(`${subject}:${policy}`, limit, windowSeconds);
  if (retryAfter !== null) throw tooManyRequests(retryAfter);
}

// The client address, which public routes cannot work without.
export function requireClientAddress(request: Request): string {
  const address = clientAddress(request);
  if (!address) throw forbidden('Client IP is required');
  return address;
}

export function rateLimit(limiter: RateLimiter, policy: RatePolicy): MiddlewareHandler {
  return async (c, next) => {
    await consume(limiter, policy, requireClientAddress(c.req.raw));
    await next();
  };
}
