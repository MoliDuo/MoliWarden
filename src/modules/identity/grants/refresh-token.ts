import { HttpError, IdentityError } from '../../../http/errors';
import { consume, type RatePolicy } from '../../../http/rate-limit';
import type { Deps } from '../../../main/deps';
import { sha256Hex } from '../../../platform/crypto';
import { recordAudit, requestMetadata } from '../../audit/service';
import { refreshSession } from '../../auth/sessions';
import { touchDevice } from '../../devices/repo';
import { tokenBody, type Tokens } from '../login';
import type { TokenForm } from '../schemas';
import { isWebSession, sessionCookie, sessionCookieToken } from '../web-session';

// Rate limits on the token endpoint answer in OAuth terms.
async function drawBudget(deps: Deps, policy: RatePolicy, subject: string): Promise<void> {
  try {
    await consume(deps.limiter, policy, subject);
  } catch (error) {
    if (!(error instanceof HttpError) || error.status !== 429) throw error;
    throw new IdentityError('temporarily_unavailable', error.message, 429, {}, error.headers);
  }
}

// Swaps a refresh token for a new access token and a new refresh token.
// Refreshes do not need a client address: mobile networks sometimes hide it.
export async function refreshTokenGrant(deps: Deps, request: Request, form: TokenForm, address: string | null): Promise<Tokens> {
  const web = isWebSession(request);
  const token = form.refresh_token.trim() || (web ? sessionCookieToken(request) : null);
  if (!token) throw new IdentityError('invalid_request', 'Refresh token is required');

  await drawBudget(deps, 'refresh-session', sha256Hex(token));
  if (address) await drawBudget(deps, 'refresh', address);

  const result = await refreshSession(deps.db, token);
  if (!result.ok) {
    await recordAudit(deps.db, {
      actorUserId: result.userId,
      action: `auth.refresh.failed.${result.reason}`,
      category: 'auth',
      level: 'warn',
      targetType: 'refreshToken',
      metadata: { grantType: 'refresh_token', reason: result.reason, webSession: web, ...requestMetadata(request) },
    });
    throw new IdentityError('invalid_grant', 'Invalid refresh token', 400, {}, web ? { 'Set-Cookie': sessionCookie(request, null) } : {});
  }

  if (result.device) await touchDevice(deps.db, result.user.id, result.device.deviceIdentifier);
  return { body: tokenBody(deps, result.user, result.device), refreshToken: result.refreshToken };
}
