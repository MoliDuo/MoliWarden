import { Hono } from 'hono';
import { authenticate, type AuthedEnv } from '../../http/authenticate';
import { readBody, readJson } from '../../http/body';
import { notImplemented } from '../../http/errors';
import { rateLimit, requireClientAddress } from '../../http/rate-limit';
import { requireSameOrigin } from '../../http/same-origin';
import type { Deps } from '../../main/deps';
import {
  emailBody,
  keysBody,
  passwordBody,
  profileBody,
  registerBody,
  secretBody,
  secretOf,
  userKeyIdBody,
  verifyPasswordBody,
} from './schemas';
import {
  apiKey,
  changePassword,
  keysJson,
  passwordHint,
  profile,
  register,
  revisionDate,
  setKeys,
  setUserKeyId,
  updateProfile,
  verifyPassword,
} from './service';

const EMAIL_UNSUPPORTED = 'Email delivery is not supported by this server.';

// Flows that confirm an email address or send a code by email.
const PUBLIC_EMAIL_PATHS = [
  '/api/accounts/resend-new-device-otp',
  '/accounts/resend-new-device-otp',
  '/api/accounts/register/send-verification-email',
  '/accounts/register/send-verification-email',
  '/identity/accounts/register/send-verification-email',
  '/api/accounts/register/verification-email-clicked',
  '/accounts/register/verification-email-clicked',
  '/identity/accounts/register/verification-email-clicked',
  '/api/accounts/register/finish',
  '/accounts/register/finish',
  '/identity/accounts/register/finish',
  '/api/accounts/verify-email-token',
  '/accounts/verify-email-token',
];
const SIGNED_IN_EMAIL_PATHS = [
  '/api/accounts/email-token',
  '/accounts/email-token',
  '/api/accounts/verify-email',
  '/accounts/verify-email',
  '/api/accounts/request-otp',
  '/accounts/request-otp',
  '/api/accounts/verify-otp',
  '/accounts/verify-otp',
];
// Deleting the account or vault, and setting a first password (SSO).
const UNSUPPORTED_PATHS = ['/api/accounts/set-password', '/api/accounts/delete', '/api/accounts/delete-account', '/api/accounts/delete-vault'];

export function accountRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);
  const sensitive = rateLimit(deps.limiter, 'sensitive');

  // Only the web vault registers accounts here; official clients use the
  // email-verified flow below, which this server cannot offer.
  app.post('/api/accounts/register', rateLimit(deps.limiter, 'register'), requireSameOrigin, async (c) =>
    c.json(await register(deps, c.req.raw, await readJson(c, registerBody))),
  );
  app.post('/api/accounts/password-hint', sensitive, requireSameOrigin, async (c) => {
    const { email } = await readJson(c, emailBody);
    return c.json(await passwordHint(deps, requireClientAddress(c.req.raw), email.trim().toLowerCase()));
  });
  for (const path of PUBLIC_EMAIL_PATHS) {
    app.post(path, sensitive, () => {
      throw notImplemented(EMAIL_UNSUPPORTED);
    });
  }

  app.get('/api/accounts/profile', authed, async (c) => c.json(await profile(deps, c.var.actor.user)));
  app.on(['PUT', 'POST'], '/api/accounts/profile', authed, async (c) =>
    c.json(await updateProfile(deps, c.req.raw, c.var.actor.user, await readJson(c, profileBody))),
  );

  app.get('/api/accounts/revision-date', authed, async (c) => c.json(await revisionDate(deps, c.var.actor.user)));

  app.get('/api/accounts/keys', authed, (c) => c.json(keysJson(c.var.actor.user)));
  app.post('/api/accounts/keys', authed, async (c) =>
    c.json(await setKeys(deps, c.req.raw, c.var.actor.user, await readJson(c, keysBody))),
  );

  for (const path of ['/api/accounts/password', '/api/accounts/change-password']) {
    app.on(['POST', 'PUT'], path, authed, async (c) => {
      await changePassword(deps, c.req.raw, c.var.actor.user, await readJson(c, passwordBody));
      return c.body(null, 200);
    });
  }

  app.post('/api/accounts/verify-password', authed, async (c) => {
    const body = await readJson(c, verifyPasswordBody);
    const secret = body.masterPasswordHash || body.authenticationData?.masterPasswordAuthenticationHash || '';
    return c.json(await verifyPassword(c.var.actor.user, secret));
  });

  app.post('/api/accounts/key-management/user-key-id', authed, async (c) => {
    await setUserKeyId(deps, c.var.actor.user, (await readJson(c, userKeyIdBody)).userKeyId);
    return c.body(null, 200);
  });

  for (const [paths, rotate] of [
    [['/api/accounts/api-key', '/api/accounts/api_key'], false],
    [['/api/accounts/rotate-api-key', '/api/accounts/rotate_api_key'], true],
  ] as const) {
    for (const path of paths) {
      app.post(path, authed, async (c) =>
        c.json(await apiKey(deps, c.req.raw, c.var.actor.user, secretOf(await readBody(c, secretBody)), rotate)),
      );
    }
  }

  // New-device verification sends codes by email.
  app.on(['PUT', 'POST'], '/api/accounts/verify-devices', authed, () => {
    throw notImplemented('New device verification is not available on this server. Enable two-step login instead.');
  });
  for (const path of ['/api/accounts/kdf', '/accounts/kdf']) {
    app.on(['POST', 'PUT'], path, authed, () => {
      throw notImplemented('KDF changes are not supported by this server.');
    });
  }
  for (const path of SIGNED_IN_EMAIL_PATHS) {
    app.on(['POST', 'PUT'], path, authed, () => {
      throw notImplemented(EMAIL_UNSUPPORTED);
    });
  }
  for (const path of UNSUPPORTED_PATHS) {
    app.on(['POST', 'PUT', 'DELETE'], path, authed, () => {
      throw notImplemented();
    });
  }

  return app;
}
