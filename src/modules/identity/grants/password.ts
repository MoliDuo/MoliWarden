import { IdentityError, invalidGrant } from '../../../http/errors';
import type { Deps } from '../../../main/deps';
import { constantTimeEqual } from '../../../platform/crypto';
import type { User } from '../../../types';
import { findUserByEmail } from '../../accounts/repo';
import { findApprovedLoginRequest, markAuthRequestUsed } from '../../auth-requests/repo';
import { accountLockoutKey, lockoutKey } from '../../auth/lockout';
import { verifyMasterPassword } from '../../auth/password';
import { findDevice } from '../../devices/repo';
import { secondStep } from '../../two-factor/login';
import {
  accountDisabled,
  assertNotLockedOut,
  auditLoginFailure,
  clearAttempts,
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
  const addressLockout = lockoutKey(address, 'password', email);
  // Checked before the lookup, so a locked-out guesser learns nothing about the account.
  await assertNotLockedOut(deps, addressLockout);

  const device = signingInDevice(form, request);
  const user = await findUserByEmail(deps.db, email);
  // A guesser spreading over many addresses still runs into a limit per
  // account. It does not apply to devices the account signed in from, so
  // the guessing cannot keep the owner out.
  const accountLockout = accountLockoutKey('password', email);
  const known = !!user && !!device.identifier && !!(await findDevice(deps.db, user.id, device.identifier));
  const lockouts = known ? [addressLockout] : [addressLockout, accountLockout];
  if (!known) await assertNotLockedOut(deps, accountLockout);

  if (!user) return failAttempt(deps, lockouts, wrongCredentials());
  if (user.status !== 'active') {
    await auditLoginFailure(deps, request, user, 'auth.login.failed.user_inactive', 'password', device);
    return failAttempt(deps, lockouts, accountDisabled());
  }

  const first = await firstStep(deps, user, form);
  if (!first.ok) {
    const reason = form.authRequest.trim() ? 'bad_auth_request' : 'bad_password';
    await auditLoginFailure(deps, request, user, `auth.login.failed.${reason}`, 'password', device);
    return failAttempt(deps, lockouts, wrongCredentials());
  }

  const second = await secondStep(deps, request, user, {
    provider: form.twoFactorProvider,
    token: form.twoFactorToken,
    remember: REMEMBER_VALUES.has(form.twoFactorRemember.trim().toLowerCase()),
    deviceIdentifier: device.identifier,
  });
  if (second.status === 'challenge') throw second.error;
  if (second.status === 'failed') return failAttempt(deps, lockouts, invalidGrant('Two-step token is invalid. Try again.'));

  // An approved request signs in once; of two concurrent logins only one gets a session.
  if (first.authRequestId && !(await markAuthRequestUsed(deps.db, first.authRequestId))) throw wrongCredentials();

  await clearAttempts(deps, [addressLockout, accountLockout]);
  return issueLogin(deps, request, {
    user,
    grantType: 'password',
    device,
    clientType: clientTypeOf(request, form.client_id),
    extras: { rememberToken: second.rememberToken, key: first.key },
  });
}
