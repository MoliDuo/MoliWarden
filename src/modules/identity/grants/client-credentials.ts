import { IdentityError, invalidGrant } from '../../../http/errors';
import type { Deps } from '../../../main/deps';
import { verifyApiKey } from '../../auth/api-key';
import { findUserById } from '../../accounts/repo';
import { lockoutKey } from '../../auth/lockout';
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

// The personal API key (client id "user.<id>"), used by the CLI and scripts.
// It skips two-step login, like upstream.
export async function clientCredentialsGrant(deps: Deps, request: Request, form: TokenForm, address: string): Promise<Tokens> {
  const clientId = form.client_id.trim();
  if (form.scope !== 'api' || !clientId.startsWith('user.') || !form.client_secret) {
    throw new IdentityError('invalid_request', 'Parameter error');
  }
  const userId = clientId.slice('user.'.length);
  const lockKey = lockoutKey(address, 'client_credentials', userId);
  await assertNotLockedOut(deps, lockKey);

  const wrongCredentials = () => invalidGrant('ClientId or clientSecret is incorrect. Try again');
  const device = signingInDevice(form, request);
  const user = await findUserById(deps.db, userId);
  if (!user) return failAttempt(deps, [lockKey], wrongCredentials());
  if (user.status !== 'active') {
    await auditLoginFailure(deps, request, user, 'auth.login.failed.user_inactive', 'client_credentials', device);
    return failAttempt(deps, [lockKey], accountDisabled());
  }
  if (!verifyApiKey(deps.secrets, user, form.client_secret)) {
    await auditLoginFailure(deps, request, user, 'auth.login.failed.bad_api_key', 'client_credentials', device);
    return failAttempt(deps, [lockKey], wrongCredentials());
  }

  await clearAttempts(deps, [lockKey]);
  return issueLogin(deps, request, {
    user,
    grantType: 'client_credentials',
    device,
    clientType: clientTypeOf(request, form.client_id),
  });
}
