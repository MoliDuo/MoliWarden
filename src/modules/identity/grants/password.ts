import { IdentityError, invalidGrant } from '../../../http/errors';
import type { Deps } from '../../../main/deps';
import { constantTimeEqual } from '../../../platform/crypto';
import type { User } from '../../../types';
import { findUserByEmail } from '../../accounts/repo';
import { findApprovedLoginRequest, markAuthRequestUsed } from '../../auth-requests/repo';
import { lockoutKey, clearFailures } from '../../auth/lockout';
import { verifyMasterPassword } from '../../auth/password';
import { secondStep } from '../../two-factor/login';
import {
  accountDisabled,
  assertNotLockedOut,
  auditLoginFailure,
  clientTypeOf,
  failAttempt,
  issueLogin,
  signingInDevice,
  type Tokens,
} from '../login';
import type { TokenForm } from '../schemas';

const wrongCredentials = () => invalidGrant('Username or password is incorrect. Try again');
const REMEMBER_VALUES = new Set(['1', 'true', 'on', 'yes']);

// Proves who the user is: the master password hash, or the access code of
// a login request another device approved (which also hands over the key).
async function firstStep(
  deps: Deps,
  user: User,
  form: TokenForm,
): Promise<{ ok: false } | { ok: true; authRequestId: string | null; key?: string }> {
  const authRequestId = form.authRequest.trim();
  if (!authRequestId) return (await verifyMasterPassword(user, form.password)) ? { ok: true, authRequestId: null } : { ok: false };
  const approved = await findApprovedLoginRequest(deps.db, authRequestId, user.id);
  if (!approved || !constantTimeEqual(approved.accessCode, form.password)) return { ok: false };
  return { ok: true, authRequestId: approved.id, key: approved.key };
}

export async function passwordGrant(deps: Deps, request: Request, form: TokenForm, address: string): Promise<Tokens> {
  const email = form.username.trim().toLowerCase();
  if (!email || !form.password) throw new IdentityError('invalid_request', 'Email and password are required');
  const lockKey = lockoutKey(address, 'password', email);
  // Checked before the lookup, so a locked-out guesser learns nothing about the account.
  await assertNotLockedOut(deps, lockKey);

  const device = signingInDevice(form, request);
  const user = await findUserByEmail(deps.db, email);
  if (!user) return failAttempt(deps, lockKey, wrongCredentials());
  if (user.status !== 'active') {
    await auditLoginFailure(deps, request, user, 'auth.login.failed.user_inactive', 'password', device);
    return failAttempt(deps, lockKey, accountDisabled());
  }

  const first = await firstStep(deps, user, form);
  if (!first.ok) {
    const reason = form.authRequest.trim() ? 'bad_auth_request' : 'bad_password';
    await auditLoginFailure(deps, request, user, `auth.login.failed.${reason}`, 'password', device);
    return failAttempt(deps, lockKey, wrongCredentials());
  }

  const second = await secondStep(deps, request, user, {
    provider: form.twoFactorProvider,
    token: form.twoFactorToken,
    remember: REMEMBER_VALUES.has(form.twoFactorRemember.trim().toLowerCase()),
    deviceIdentifier: device.identifier,
  });
  if (second.status === 'challenge') throw second.error;
  if (second.status === 'failed') return failAttempt(deps, lockKey, invalidGrant('Two-step token is invalid. Try again.'));

  // An approved request signs in once; of two concurrent logins only one gets a session.
  if (first.authRequestId && !(await markAuthRequestUsed(deps.db, first.authRequestId))) throw wrongCredentials();

  await clearFailures(deps.limiter, lockKey);
  return issueLogin(deps, request, {
    user,
    grantType: 'password',
    device,
    clientType: clientTypeOf(request, form.client_id),
    extras: { rememberToken: second.rememberToken, key: first.key },
  });
}
