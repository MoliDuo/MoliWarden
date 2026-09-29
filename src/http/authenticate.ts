import type { Context, MiddlewareHandler } from 'hono';
import type { Deps } from '../main/deps';
import type { AccessClaims } from '../modules/auth/access-token';
import { findSession } from '../modules/auth/repo';
import type { TokenType } from '../platform/tokens';
import type { Device, User } from '../types';
import { forbidden, unauthorized } from './errors';
import { consume, type RatePolicy } from './rate-limit';

// The signed-in user a request acts for and the device it was issued to.
export interface Actor {
  user: User;
  device: Device | null;
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

// The stamps a token carries to end it early: `sstamp` changes with the
// password or 2FA settings, `dstamp` when the device is logged out.
type SessionClaims = Pick<AccessClaims, 'sub' | 'sstamp' | 'did' | 'dstamp'>;

// Checks the claims against the current state of the account and draws
// from the user's `policy` budget. Nothing is cached, so a ban or a logout
// holds on every instance immediately.
async function actAs(deps: Deps, c: Context<AuthedEnv>, claims: SessionClaims, policy: RatePolicy): Promise<void> {
  const session = await findSession(deps.db, claims.sub, claims.did ?? null);
  if (!session || session.user.status !== 'active' || session.user.securityStamp !== claims.sstamp) {
    throw unauthorized();
  }
  if (claims.did && (!session.device || session.device.sessionStamp !== claims.dstamp)) throw unauthorized();
  await consume(deps.limiter, policy, session.user.id);
  c.set('actor', session);
}

export function authenticate(deps: Deps, policy: RatePolicy = 'api'): MiddlewareHandler<AuthedEnv> {
  return async (c, next) => {
    const [scheme, token] = (c.req.header('Authorization') ?? '').split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) throw unauthorized();
    const claims = deps.tokens.verify<AccessClaims>('access', token);
    if (!claims) throw unauthorized();
    await actAs(deps, c, claims, policy);
    await next();
  };
}

// File uploads go to the URL the server handed out (see uploadUrl), whose
// token is good for the one file `fileOf` names. Without a token, the
// bearer token is required.
export function authenticateUpload(
  deps: Deps,
  typ: Extract<TokenType, 'attachment-upload' | 'send-upload'>,
  fileOf: (c: Context) => string,
): MiddlewareHandler<AuthedEnv> {
  const bearer = authenticate(deps, 'bulk');
  return async (c, next) => {
    const token = c.req.query('token');
    if (!token) return bearer(c, next);
    const claims = deps.tokens.verify<SessionClaims & { file: string }>(typ, token);
    if (!claims) throw unauthorized('Invalid or expired token');
    if (claims.file !== fileOf(c)) throw unauthorized('Token mismatch');
    await actAs(deps, c, claims, 'bulk');
    await next();
  };
}

// For admin-only routes; runs after authenticate().
export const requireAdmin: MiddlewareHandler<AuthedEnv> = async (c, next) => {
  if (c.var.actor.user.role !== 'admin') throw forbidden();
  await next();
};
