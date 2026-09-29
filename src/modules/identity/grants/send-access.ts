import { HttpError, IdentityError } from '../../../http/errors';
import { consume } from '../../../http/rate-limit';
import type { Deps } from '../../../main/deps';
import { issueSendAccessToken, SEND_ACCESS_TOKEN_TTL_SECONDS } from '../../sends/access';
import type { TokenForm } from '../schemas';

// Opens a Send for an anonymous recipient, with its password when it has one.
export async function sendAccessGrant(deps: Deps, form: TokenForm, address: string): Promise<Record<string, unknown>> {
  try {
    await consume(deps.limiter, 'public', address);
  } catch (error) {
    if (error instanceof HttpError && error.status === 429) throw new IdentityError('TooManyRequests', error.message, 429, {}, error.headers);
    throw error;
  }

  const sendId = form.send_id.trim();
  if (!sendId) {
    throw new IdentityError('invalid_request', 'send_id is required', 400, { send_access_error_type: 'send_id_required' });
  }
  const password = (form.password_hash_b64 || form.password).trim() || null;
  return {
    access_token: await issueSendAccessToken(deps, address, sendId, password),
    expires_in: SEND_ACCESS_TOKEN_TTL_SECONDS,
    token_type: 'Bearer',
    scope: 'api.send',
    unofficialServer: true,
  };
}
