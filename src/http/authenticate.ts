import type { Context, MiddlewareHandler } from 'hono';
import type { Deps } from '../main/deps';
import type { AccessClaims } from '../modules/auth/access-token';
import { findSession } from '../modules/auth/repo';
import type { Device, User } from '../types';
import { forbidden, unauthorized } from './errors';
import { consume, type RatePolicy } from './rate-limit';

// The signed-in user a request acts for and the device it was issued to.
export interface Actor {
  user: User;
  device: Device | null;
  claims: AccessClaims;
}

export type AuthedEnv = { Variables: { actor: Actor } };

// Who a vault change is made by, as services see it: the device is left
// out of the push notifications the change causes.
export interface Caller {
  user: User;
  device: string | null;
  request: Request;
}

export const callerOf = (c: Context<AuthedEnv>): Caller => ({
  user: c.var.actor.user,
  device: c.var.actor.device?.deviceIdentifier ?? null,
  request: c.req.raw,
});

// Verifies the bearer token against the current state of the account: a
// changed security stamp (password, 2FA), a logged-out device or a ban
// ends every access token at once. Nothing is cached, so this holds on
// every instance immediately. Each request then draws from the user's
// `policy` budget.
export function authenticate(deps: Deps, policy: RatePolicy = 'api'): MiddlewareHandler<AuthedEnv> {
  return async (c, next) => {
    const [scheme, token] = (c.req.header('Authorization') ?? '').split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) throw unauthorized();
    const claims = deps.tokens.verify<AccessClaims>('access', token);
    if (!claims) throw unauthorized();

    const session = await findSession(deps.db, claims.sub, claims.did ?? null);
    if (!session || session.user.status !== 'active' || session.user.securityStamp !== claims.sstamp) {
      throw unauthorized();
    }
    if (claims.did && (!session.device || session.device.sessionStamp !== claims.dstamp)) throw unauthorized();

    await consume(deps.limiter, policy, session.user.id);
    c.set('actor', { ...session, claims });
    await next();
  };
}

// For admin-only routes; runs after authenticate().
export const requireAdmin: MiddlewareHandler<AuthedEnv> = async (c, next) => {
  if (c.var.actor.user.role !== 'admin') throw forbidden();
  await next();
};
