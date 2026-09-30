import type { TokenService } from '../../platform/tokens';
import type { User } from '../../types';

// Short-lived proof that the user just verified themselves (master password
// or passkey), redeemable once for one purpose. A changed security stamp
// voids it.

export type VerificationPurpose =
  // Setting up an authenticator app with the key shown alongside the token.
  | 'totp.setup'
  // Repairing backup settings after signing in with a passkey.
  | 'backup.settings.repair';

interface VerificationClaims {
  sub: string;
  purpose: VerificationPurpose;
  sstamp: string;
  // What the verification covers, such as the authenticator key on setup.
  subject?: string;
}

const TTL_SECONDS: Record<VerificationPurpose, number> = {
  'totp.setup': 10 * 60,
  'backup.settings.repair': 5 * 60,
};

export function signUserVerification(
  tokens: TokenService,
  user: Pick<User, 'id' | 'securityStamp'>,
  purpose: VerificationPurpose,
  subject?: string,
): string {
  const claims: VerificationClaims = { sub: user.id, purpose, sstamp: user.securityStamp, ...(subject ? { subject } : {}) };
  return tokens.sign('user-verification', claims, TTL_SECONDS[purpose]);
}

export function verifyUserVerification(
  tokens: TokenService,
  token: string | null | undefined,
  user: Pick<User, 'id' | 'securityStamp'>,
  purpose: VerificationPurpose,
  subject?: string,
): boolean {
  const claims = tokens.verify<VerificationClaims>('user-verification', token);
  return (
    !!claims &&
    claims.sub === user.id &&
    claims.purpose === purpose &&
    claims.sstamp === user.securityStamp &&
    claims.subject === subject
  );
}
