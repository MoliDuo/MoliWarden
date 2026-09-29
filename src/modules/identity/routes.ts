import { Hono, type Context } from 'hono';
import { LIMITS } from '../../config/limits';
import { readBody, readJson } from '../../http/body';
import { clientAddress } from '../../http/client';
import { badRequest, IdentityError } from '../../http/errors';
import { rateLimit } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { findUserByEmail } from '../accounts/repo';
import { recordAudit, requestMetadata } from '../audit/service';
import { revokeSession } from '../auth/sessions';
import { loginAssertionOptions } from '../passkeys/service';
import { clientCredentialsGrant } from './grants/client-credentials';
import { passwordGrant } from './grants/password';
import { refreshTokenGrant } from './grants/refresh-token';
import { sendAccessGrant } from './grants/send-access';
import { webAuthnGrant } from './grants/webauthn';
import type { Tokens } from './login';
import { preloginBody, revocationForm, tokenForm, type TokenForm } from './schemas';
import { isWebSession, sessionCookie, sessionCookieToken } from './web-session';

// The OAuth side of the server: signing in, refreshing and signing out.

type Grant = (deps: Deps, request: Request, form: TokenForm, address: string) => Promise<Tokens>;

const LOGIN_GRANTS: Record<string, Grant> = {
  password: passwordGrant,
  webauthn: webAuthnGrant,
  client_credentials: clientCredentialsGrant,
};

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

// The web vault gets its refresh token as a cookie, everyone else in the body.
function respondWithTokens(c: Context, tokens: Tokens): Response {
  if (!isWebSession(c.req.raw)) return c.json({ ...tokens.body, refresh_token: tokens.refreshToken }, 200, NO_STORE);
  return c.json({ ...tokens.body, web_session: true }, 200, { ...NO_STORE, 'Set-Cookie': sessionCookie(c.req.raw, tokens.refreshToken) });
}

async function readTokenForm(c: Context): Promise<TokenForm> {
  try {
    return await readBody(c, tokenForm);
  } catch {
    throw new IdentityError('invalid_request', 'Invalid request payload');
  }
}

export function identityRoutes(deps: Deps): Hono {
  const app = new Hono();
  const sensitive = rateLimit(deps.limiter, 'sensitive');

  app.post('/identity/connect/token', async (c) => {
    const request = c.req.raw;
    const form = await readTokenForm(c);
    const address = clientAddress(request);
    if (form.grant_type === 'refresh_token') return respondWithTokens(c, await refreshTokenGrant(deps, request, form, address));

    // Every other grant is throttled per client address and cannot work without one.
    if (!address) {
      await recordAudit(deps.db, {
        action: 'auth.client_ip.missing',
        category: 'auth',
        level: 'error',
        targetType: 'tokenEndpoint',
        metadata: { grantType: form.grant_type, reason: 'client_ip_missing', ...requestMetadata(request) },
      });
      throw new IdentityError('temporarily_unavailable', 'Authentication is temporarily unavailable', 503, {}, { 'Retry-After': '5' });
    }

    if (form.grant_type === 'send_access') {
      return c.json(await sendAccessGrant(deps, form, address), 200, NO_STORE);
    }
    const grant = LOGIN_GRANTS[form.grant_type];
    if (!grant) throw new IdentityError('unsupported_grant_type', 'Unsupported grant type');
    return respondWithTokens(c, await grant(deps, request, form, address));
  });

  // RFC 7009: unknown tokens are not an error.
  for (const path of ['/identity/connect/revocation', '/identity/connect/revoke']) {
    app.post(path, sensitive, async (c) => {
      const web = isWebSession(c.req.raw);
      const form = await readBody(c, revocationForm).catch(() => null);
      const token = form?.token.trim() || (web ? sessionCookieToken(c.req.raw) : null);
      if (token) await revokeSession(deps.db, token);
      return c.body(null, 200, web ? { ...NO_STORE, 'Set-Cookie': sessionCookie(c.req.raw, null) } : NO_STORE);
    });
  }

  // How to derive the master key. Unknown accounts get the defaults, so the
  // answer does not tell whether an account exists.
  for (const path of ['/identity/accounts/prelogin', '/api/accounts/prelogin', '/identity/accounts/prelogin/password']) {
    app.post(path, sensitive, async (c) => {
      const email = (await readJson(c, preloginBody)).email.trim().toLowerCase();
      if (!email) throw badRequest('Email is required');
      const user = await findUserByEmail(deps.db, email);
      const kdfType = user?.kdfType ?? 0;
      const iterations = user?.kdfIterations ?? LIMITS.auth.defaultKdfIterations;
      const memory = user?.kdfMemory ?? null;
      const parallelism = user?.kdfParallelism ?? null;
      return c.json(
        {
          kdf: kdfType,
          kdfIterations: iterations,
          kdfMemory: memory,
          kdfParallelism: parallelism,
          kdfSettings: { kdfType, iterations, memory, parallelism },
          salt: null,
          KdfSettings: { KdfType: kdfType, Iterations: iterations, Memory: memory, Parallelism: parallelism },
          Salt: email,
        },
        200,
        NO_STORE,
      );
    });
  }

  // Starts a passwordless login with a passkey.
  app.get('/identity/accounts/webauthn/assertion-options', sensitive, async (c) => {
    const { options, token } = await loginAssertionOptions(deps, c.req.raw);
    return c.json({ options, token, object: 'webAuthnLoginAssertionOptions', Object: 'webAuthnLoginAssertionOptions' });
  });

  return app;
}
