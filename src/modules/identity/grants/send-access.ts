import { LIMITS } from '../../../config/limits';
import { HttpError, IdentityError } from '../../../http/errors';
import { consume } from '../../../http/rate-limit';
import type { Deps } from '../../../main/deps';
import { issueSendAccessToken } from '../../../handlers/sends';
import { RateLimitService } from '../../../services/ratelimit';
import type { TokenForm } from '../schemas';

// Opens a Send for an anonymous recipient, with its password when it has one.
// Until Sends move to src/modules, the Send checks stay in the old handler,
// which answers failures with a ready response.
export async function sendAccessGrant(deps: Deps, form: TokenForm, address: string): Promise<Record<string, unknown> | Response> {
  try {
    await consume(deps.limiter, 'public', address);
  } catch (error) {
    if (error instanceof HttpError && error.status === 429) throw new IdentityError('TooManyRequests', error.message, 429, {}, error.headers);
    throw error;
  }

  const sendId = (form.send_id || form.sendId).trim();
  if (!sendId) {
    throw new IdentityError('invalid_request', 'send_id is required', 400, { send_access_error_type: 'send_id_required' });
  }
  const passwordHashB64 = (form.password_hash_b64 || form.passwordHashB64 || form.passwordHash || form.password_hash).trim() || null;
  const password = form.password.trim() || null;

  const result = await issueSendAccessToken(
    deps.legacyEnv,
    sendId,
    passwordHashB64,
    password,
    new RateLimitService(deps.legacyEnv.DB),
    address,
  );
  if ('error' in result) return result.error;
  return {
    access_token: result.token,
    expires_in: LIMITS.auth.sendAccessTokenTtlSeconds,
    token_type: 'Bearer',
    scope: 'api.send',
    unofficialServer: true,
  };
}
