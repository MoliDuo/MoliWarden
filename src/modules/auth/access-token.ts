import { LIMITS } from '../../config/limits';
import type { Executor } from '../../platform/db';
import type { TokenService } from '../../platform/tokens';
import type { Device, User } from '../../types';
import { findSession } from './repo';

// The claims official clients read from an access token, plus the stamps
// that end it early: `sstamp` changes with the password or 2FA settings,
// `dstamp` when the device is logged out.
export interface AccessClaims {
  sub: string;
  email: string;
  name: string | null;
  sstamp: string;
  did?: string;
  dstamp?: string;
  email_verified: true;
  amr: string[];
  iss: string;
  premium: true;
}

export function signAccessToken(
  tokens: TokenService,
  user: Pick<User, 'id' | 'email' | 'name' | 'securityStamp'>,
  device: Pick<Device, 'deviceIdentifier' | 'sessionStamp'> | null,
): string {
  const claims: AccessClaims = {
    sub: user.id,
    email: user.email,
    name: user.name,
    sstamp: user.securityStamp,
    ...(device ? { did: device.deviceIdentifier, dstamp: device.sessionStamp } : {}),
    // The mobile apps refuse tokens without these.
    email_verified: true,
    amr: ['Application'],
    iss: 'moliwarden',
    premium: true,
  };
  return tokens.sign('access', claims, LIMITS.auth.accessTokenTtlSeconds);
}

// The user and device a token is still good for, checked against the
// current state of the account: null once the user is no longer active, the
// password or 2FA settings changed, or the device was logged out. Nothing is
// cached, so that holds on every instance immediately.
export type SessionClaims = Pick<AccessClaims, 'sub' | 'sstamp' | 'did' | 'dstamp'>;

export async function sessionOf(
  db: Executor,
  claims: SessionClaims,
): Promise<{ user: User; device: Device | null } | null> {
  const session = await findSession(db, claims.sub, claims.did ? { identifier: claims.did } : null);
  if (!session || session.user.status !== 'active' || session.user.securityStamp !== claims.sstamp) return null;
  if (claims.did && (!session.device || session.device.sessionStamp !== claims.dstamp)) return null;
  return session;
}
