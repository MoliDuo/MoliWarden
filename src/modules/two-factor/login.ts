import { IdentityError } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { randomToken, sha256 } from '../../platform/crypto';
import type { User } from '../../types';
import { securityKeyAssertionOptions, verifySecurityKeyAssertion } from '../passkeys/service';
import { hasRememberToken, saveRememberToken } from './repo';
import { openTotpSecret } from './secrets';
import {
  checkYubiKeyOtp,
  factorsOf,
  hasSecondFactor,
  Provider,
  recoveryCodeValid,
  resetTwoFactor,
  useTotpCode,
  type Factors,
} from './service';
import { yubiKeyPublicId } from './yubico';

// The second step of a password login. Each provider a client may answer
// with is one entry of the table below.

const REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// Recovery codes arrive as 8 (the Identity enum), -1 (the web settings
// dialog) or 100 (Android).
const RECOVERY_CODE_PROVIDERS = new Set(['8', '-1', '100']);

export interface SecondStep {
  provider: string | null;
  token: string | null;
  remember: boolean;
  deviceIdentifier: string | null;
}

export type SecondStepResult =
  // Passed, or not needed. `rememberToken` lets this device skip the step next time.
  | { status: 'passed'; rememberToken: string | null }
  // The client has to ask the user; the error carries what for.
  | { status: 'challenge'; error: IdentityError }
  // A wrong answer, which counts as a failed login.
  | { status: 'failed' };

interface Check {
  deps: Deps;
  request: Request;
  user: User;
  factors: Factors;
  token: string;
}

// Each provider checks the answer; true means it passed.
const CHECKS: Record<number, (check: Check) => Promise<boolean>> = {
  async [Provider.Authenticator]({ deps, user, factors, token }) {
    if (!factors.totp) return false;
    return useTotpCode(deps.db, user.id, openTotpSecret(deps.secrets, user.id, factors.totp.secret), token);
  },
  async [Provider.YubiKey]({ deps, user, factors, token }) {
    const publicId = yubiKeyPublicId(token);
    return !!publicId && factors.yubiKeys.includes(publicId) && (await checkYubiKeyOtp(deps, user.email, token));
  },
  async [Provider.WebAuthn]({ deps, request, user, factors, token }) {
    if (!factors.securityKeys.length) return false;
    let response: unknown;
    try {
      response = JSON.parse(token);
    } catch {
      return false;
    }
    return verifySecurityKeyAssertion(deps, request, user.id, response);
  },
};

// What the client needs to show for each provider the user has set up.
async function challenge(deps: Deps, request: Request, user: User, factors: Factors): Promise<IdentityError> {
  const providers: Record<string, unknown> = {};
  if (factors.totp) providers[Provider.Authenticator] = null;
  if (factors.yubiKeys.length) providers[Provider.YubiKey] = { Nfc: factors.yubiKey?.nfc ?? false };
  const webAuthn = await securityKeyAssertionOptions(deps, request, factors.securityKeys);
  if (webAuthn) providers[Provider.WebAuthn] = webAuthn;
  return twoFactorRequired(providers);
}

// The shape official clients recognize as "ask for a second factor".
// TwoFactorProviders2 lists enabled providers only: Android fails to parse
// the challenge when it names the recovery code.
export function twoFactorRequired(providers: Record<string, unknown>, message = 'Two factor required.'): IdentityError {
  const custom = {
    TwoFactorProviders: Object.keys(providers),
    TwoFactorProviders2: providers,
    SsoEmail2faSessionToken: null,
    MasterPasswordPolicy: masterPasswordPolicy(),
  };
  return new IdentityError('invalid_grant', message, 400, {
    Error: 'invalid_grant',
    ErrorDescription: message,
    ErrorMessage: message,
    ...custom,
    CustomResponse: custom,
  });
}

export function masterPasswordPolicy() {
  return {
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
    Object: 'masterPasswordPolicy',
    object: 'masterPasswordPolicy',
  };
}

export async function secondStep(deps: Deps, request: Request, user: User, input: SecondStep): Promise<SecondStepResult> {
  const factors = await factorsOf(deps.db, user);
  if (!hasSecondFactor(factors)) return { status: 'passed', rememberToken: null };

  const provider = input.provider?.trim() ?? '';
  const token = input.token?.trim() ?? '';
  if (!provider || !token) return { status: 'challenge', error: await challenge(deps, request, user, factors) };

  // A remembered device skips the step; a stale token just asks again.
  if (provider === String(Provider.Remember)) {
    const remembered =
      !!input.deviceIdentifier &&
      (await hasRememberToken(deps.db, sha256(token), user.id, input.deviceIdentifier, user.securityStamp));
    return remembered
      ? { status: 'passed', rememberToken: null }
      : { status: 'challenge', error: await challenge(deps, request, user, factors) };
  }

  // The recovery code turns two-step login off, so there is nothing to remember.
  if (RECOVERY_CODE_PROVIDERS.has(provider)) {
    if (!recoveryCodeValid(deps, user, token)) return { status: 'failed' };
    await resetTwoFactor(deps, user);
    return { status: 'passed', rememberToken: null };
  }

  const check = CHECKS[Number(provider)];
  if (!check || !(await check({ deps, request, user, factors, token }))) return { status: 'failed' };

  if (!input.remember || !input.deviceIdentifier) return { status: 'passed', rememberToken: null };
  const rememberToken = randomToken();
  await saveRememberToken(
    deps.db,
    sha256(rememberToken),
    user.id,
    input.deviceIdentifier,
    user.securityStamp,
    new Date(Date.now() + REMEMBER_TTL_MS),
  );
  return { status: 'passed', rememberToken };
}
