import { LIMITS } from '../../config/limits';
import type { TokenService } from '../../platform/tokens';
import type { Device, User } from '../../types';

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
