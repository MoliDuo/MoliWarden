import { Hono } from 'hono';
import { authenticate, type AuthedEnv } from '../../http/authenticate';
import { readBody, readJson } from '../../http/body';
import { badRequest, notImplemented } from '../../http/errors';
import { rateLimit, requireClientAddress } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { recordAudit, requestMetadata } from '../audit/service';
import {
  authenticatorBody,
  deviceVerificationBody,
  disableBody,
  recoverBody,
  recoveryCodeBody,
  secretBody,
  secretOf,
  securityKeyBody,
  securityKeyDeleteBody,
  totpBody,
  yubicoBootstrapBody,
  yubicoConfigBody,
  yubiKeyBody,
} from './schemas';
import {
  authenticatorSetup,
  bootstrapYubico,
  configureYubico,
  disableProvider,
  enableAuthenticator,
  enableYubiKeys,
  isTotpEnabled,
  listProviders,
  Provider,
  readSecurityKeys,
  readYubiKeySettings,
  recoverWithCode,
  registerSecurityKey,
  removeSecurityKey,
  revealRecoveryCode,
  securityKeyChallenge,
  setTotp,
} from './service';

// New-device verification sends codes by email, which this server cannot.
const deviceVerificationSettings = {
  Enabled: false,
  enabled: false,
  VerifyDevices: false,
  verifyDevices: false,
  Object: 'deviceVerificationSettings',
  object: 'deviceVerificationSettings',
};

const both = (path: string) => [`/api/two-factor/${path}`, `/two-factor/${path}`];
const yubiKeyPaths = (suffix = '') => [`/api/two-factor/yubikey${suffix}`, `/api/two-factor/yubi-key${suffix}`];

export function twoFactorRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);
  const sensitive = rateLimit(deps.limiter, 'sensitive');

  app.get('/api/two-factor', authed, async (c) => c.json(await listProviders(deps, c.var.actor.user)));

  app.on(['PUT', 'POST'], '/api/two-factor/disable', authed, async (c) => {
    const body = await readBody(c, disableBody);
    return c.json(await disableProvider(deps, c.req.raw, c.var.actor.user, body.type, secretOf(body)));
  });

  // Authenticator app.
  app.post('/api/two-factor/get-authenticator', authed, async (c) => {
    const body = await readBody(c, secretBody);
    return c.json(await authenticatorSetup(deps, c.var.actor.user, secretOf(body)));
  });
  app.on(['PUT', 'POST'], '/api/two-factor/authenticator', authed, async (c) => {
    const body = await readBody(c, authenticatorBody);
    return c.json(await enableAuthenticator(deps, c.req.raw, c.var.actor.user, body));
  });
  app.delete('/api/two-factor/authenticator', authed, async (c) => {
    const body = await readBody(c, secretBody);
    return c.json(await disableProvider(deps, c.req.raw, c.var.actor.user, Provider.Authenticator, secretOf(body)));
  });

  // The web vault's authenticator endpoints.
  app.get('/api/accounts/totp', authed, async (c) => c.json({ enabled: await isTotpEnabled(deps, c.var.actor.user), object: 'twoFactor' }));
  app.on(['PUT', 'POST'], '/api/accounts/totp', authed, async (c) => {
    const body = await readJson(c, totpBody);
    return c.json(await setTotp(deps, c.req.raw, c.var.actor.user, body));
  });

  // YubiKey.
  for (const path of ['/api/two-factor/get-yubikey', '/api/two-factor/get-yubi-key']) {
    app.post(path, authed, async (c) => {
      const body = await readBody(c, secretBody);
      return c.json(await readYubiKeySettings(deps, c.var.actor.user, secretOf(body)));
    });
  }
  for (const path of yubiKeyPaths()) {
    app.on(['PUT', 'POST'], path, authed, async (c) => {
      const body = await readBody(c, yubiKeyBody);
      const keys = [body.key1, body.key2, body.key3, body.key4, body.key5];
      return c.json(await enableYubiKeys(deps, c.req.raw, c.var.actor.user, { secret: secretOf(body), keys, nfc: body.nfc }));
    });
    app.delete(path, authed, async (c) => {
      const body = await readBody(c, secretBody);
      return c.json(await disableProvider(deps, c.req.raw, c.var.actor.user, Provider.YubiKey, secretOf(body)));
    });
  }
  for (const path of yubiKeyPaths('/config')) {
    app.on(['PUT', 'POST'], path, authed, async (c) => {
      const body = await readBody(c, yubicoConfigBody);
      return c.json(
        await configureYubico(deps, c.req.raw, c.var.actor.user, {
          secret: secretOf(body),
          clientId: (body.yubicoClientId || body.clientId).trim(),
          secretKey: (body.yubicoSecretKey || body.secretKey).trim(),
        }),
      );
    });
  }
  for (const path of yubiKeyPaths('/bootstrap')) {
    app.post(path, authed, async (c) => {
      const body = await readBody(c, yubicoBootstrapBody);
      const secret = body.masterPasswordHash || body.secret || null;
      return c.json(await bootstrapYubico(deps, c.req.raw, c.var.actor.user, { secret, otp: (body.otp || body.token).trim() }));
    });
  }

  // Security keys (WebAuthn).
  app.post('/api/two-factor/get-webauthn', authed, async (c) => {
    const body = await readJson(c, secretBody);
    return c.json(await readSecurityKeys(deps, c.var.actor.user, secretOf(body)));
  });
  app.post('/api/two-factor/get-webauthn-challenge', authed, async (c) => {
    const body = await readJson(c, secretBody);
    return c.json(await securityKeyChallenge(deps, c.req.raw, c.var.actor.user, secretOf(body)));
  });
  app.on(['PUT', 'POST'], '/api/two-factor/webauthn', authed, async (c) => {
    const body = await readJson(c, securityKeyBody);
    return c.json(
      await registerSecurityKey(deps, c.req.raw, c.var.actor.user, {
        secret: secretOf(body),
        deviceResponse: body.deviceResponse,
        name: body.name.trim().slice(0, 128) || null,
      }),
    );
  });
  app.delete('/api/two-factor/webauthn', authed, async (c) => {
    const body = await readJson(c, securityKeyDeleteBody);
    return c.json(await removeSecurityKey(deps, c.req.raw, c.var.actor.user, { secret: secretOf(body), id: body.id }));
  });

  // Recovery code.
  for (const path of ['/api/two-factor/get-recover', '/api/accounts/totp/recovery-code']) {
    app.post(path, authed, async (c) => {
      const body = await readBody(c, recoveryCodeBody);
      const secret = (body.masterPasswordHash || body.master_password_hash || body.password).trim() || null;
      return c.json(await revealRecoveryCode(deps, c.var.actor.user, secret));
    });
  }
  for (const path of ['/identity/accounts/recover-2fa', '/api/accounts/recover-2fa']) {
    app.post(path, sensitive, async (c) => {
      const body = await readBody(c, recoverBody);
      return c.json(
        await recoverWithCode(deps, c.req.raw, requireClientAddress(c.req.raw), {
          email: (body.email || body.username).trim().toLowerCase(),
          masterPasswordHash: (body.masterPasswordHash || body.password).trim(),
          recoveryCode: body.recoveryCode || body.twoFactorToken || body.recovery_code,
        }),
      );
    });
  }

  // New-device verification is always off.
  app.post('/api/two-factor/get-device-verification-settings', authed, (c) => c.json(deviceVerificationSettings));
  app.on(['PUT', 'POST'], '/api/two-factor/device-verification-settings', authed, async (c) => {
    const body = await readBody(c, deviceVerificationBody);
    const requested = body.enabled ?? body.verifyDevices;
    const { user } = c.var.actor;
    await recordAudit(deps.db, {
      actorUserId: user.id,
      action: 'account.verify_devices.update.rejected',
      category: 'security',
      targetType: 'user',
      targetId: user.id,
      metadata: { requested, reason: 'new-device verification needs email delivery', ...requestMetadata(c.req.raw) },
    });
    if (requested === true) {
      throw badRequest(
        'New device verification is not available on this server. Enable TOTP or WebAuthn two-factor authentication instead.',
      );
    }
    return c.json(deviceVerificationSettings);
  });

  // Email codes need a mail service.
  const noEmail = () => {
    throw notImplemented('Email two-step login is not supported by this server.');
  };
  for (const path of [...both('get-email'), ...both('send-email'), ...both('email')]) {
    app.on(['POST', 'PUT', 'DELETE'], path, authed, noEmail);
  }
  for (const path of both('send-email-login')) {
    app.post(path, sensitive, () => {
      throw notImplemented('Email delivery is not supported by this server.');
    });
  }

  return app;
}
