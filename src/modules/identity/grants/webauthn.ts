import { IdentityError, invalidGrant } from '../../../http/errors';
import type { Deps } from '../../../main/deps';
import { recordAudit, requestMetadata } from '../../audit/service';
import { lockoutKey } from '../../auth/lockout';
import { signUserVerification } from '../../auth/user-verification';
import { PasskeyRejected, verifyLoginAssertion } from '../../passkeys/service';
import { prfDecryptionOption } from '../../passkeys/webauthn';
import { accountDisabled, assertNotLockedOut, clearAttempts, clientTypeOf, failAttempt, issueLogin, signingInDevice, type Tokens } from '../login';
import type { TokenForm } from '../schemas';

// Passwordless login with a passkey. A passkey with PRF keys also unlocks
// the vault, and proves presence well enough to repair backup settings.
export async function webAuthnGrant(deps: Deps, request: Request, form: TokenForm, address: string): Promise<Tokens> {
  const token = form.token.trim();
  const lockKey = lockoutKey(address, 'webauthn', token || 'missing-token');
  await assertNotLockedOut(deps, lockKey);

  let deviceResponse = form.deviceResponse;
  if (typeof deviceResponse === 'string') {
    try {
      deviceResponse = JSON.parse(deviceResponse);
    } catch {
      throw new IdentityError('invalid_request', 'Invalid passkey response');
    }
  }
  if (!token || !deviceResponse) throw new IdentityError('invalid_request', 'Passkey token and deviceResponse are required');

  let asserted: Awaited<ReturnType<typeof verifyLoginAssertion>>;
  try {
    asserted = await verifyLoginAssertion(deps, request, { token, deviceResponse, scope: 'Authentication' });
  } catch (error) {
    if (!(error instanceof PasskeyRejected)) throw error;
    await recordAudit(deps.db, {
      action: 'auth.passkey.login.failed',
      category: 'auth',
      level: 'warn',
      targetType: 'accountPasskey',
      metadata: { grantType: 'webauthn', reason: error.message, ...requestMetadata(request) },
    });
    return failAttempt(deps, [lockKey], invalidGrant('Passkey is invalid. Try again'));
  }

  const { user, passkey } = asserted;
  if (user.status !== 'active') return failAttempt(deps, [lockKey], accountDisabled());

  await clearAttempts(deps, [lockKey]);
  return issueLogin(deps, request, {
    user,
    grantType: 'webauthn',
    device: signingInDevice(form, request),
    clientType: clientTypeOf(request, form.client_id),
    auditAction: 'auth.passkey.login.success',
    auditTarget: { type: 'accountPasskey', id: passkey.id },
    extras: {
      prfOption: prfDecryptionOption(passkey),
      userVerificationToken: signUserVerification(deps.tokens, user, 'backup.settings.repair'),
    },
  });
}
