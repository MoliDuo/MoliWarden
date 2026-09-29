import { Hono } from 'hono';
import { authenticate, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { badRequest } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { assertionOptionsBody, createBody, passkeySecretOf, prfKeySetOf, secretBody, updateKeysBody } from './schemas';
import {
  createLoginPasskey,
  deleteLoginPasskey,
  keySetUpdateOptions,
  listLoginPasskeys,
  loginPasskeyCreationOptions,
  updateLoginPasskeyKeys,
} from './service';
import { accountPasskeyJson } from './webauthn';

// Passkeys that sign in to the account, managed from the web vault.

const both = (suffix = '') => [`/api/webauthn${suffix}`, `/webauthn${suffix}`];
const invalidKeySet = () => badRequest('Invalid encrypted passkey key set');

export function passkeyRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);

  for (const path of both()) {
    app.get(path, authed, async (c) => {
      const data = (await listLoginPasskeys(deps.db, c.var.actor.user.id)).map(accountPasskeyJson);
      return c.json({ data, Data: data, object: 'list', Object: 'list', continuationToken: null, ContinuationToken: null });
    });

    app.post(path, authed, async (c) => {
      const body = await readJson(c, createBody);
      const keys = prfKeySetOf(body);
      if (keys === 'invalid') throw invalidKeySet();
      const passkey = await createLoginPasskey(deps, c.req.raw, c.var.actor.user.id, {
        token: body.token.trim(),
        deviceResponse: body.deviceResponse,
        name: body.name,
        supportsPrf: body.supportsPrf,
        keys,
      });
      return c.json(accountPasskeyJson(passkey));
    });

    app.put(path, authed, async (c) => {
      const body = await readJson(c, updateKeysBody);
      const keys = prfKeySetOf(body);
      if (keys === 'invalid') throw invalidKeySet();
      if (!keys) throw badRequest('Encrypted passkey key set is required');
      await updateLoginPasskeyKeys(deps, c.req.raw, c.var.actor.user.id, {
        token: body.token.trim(),
        deviceResponse: body.deviceResponse,
        keys,
      });
      return c.json({ success: true });
    });
  }

  for (const path of both('/attestation-options')) {
    app.post(path, authed, async (c) => {
      const body = await readJson(c, secretBody);
      const { options, token } = await loginPasskeyCreationOptions(deps, c.req.raw, c.var.actor.user, passkeySecretOf(body));
      return c.json({ options, token, object: 'webauthnCredentialCreateOptions', Object: 'webauthnCredentialCreateOptions' });
    });
  }

  for (const path of both('/assertion-options')) {
    app.post(path, authed, async (c) => {
      const body = await readJson(c, assertionOptionsBody);
      const { options, token } = await keySetUpdateOptions(deps, c.req.raw, c.var.actor.user, {
        secret: passkeySecretOf(body),
        passkeyId: (body.credentialId || body.id).trim() || null,
      });
      return c.json({ options, token, object: 'webAuthnLoginAssertionOptions', Object: 'webAuthnLoginAssertionOptions' });
    });
  }

  for (const path of both('/:id/delete')) {
    app.post(path, authed, async (c) => {
      const body = await readJson(c, secretBody);
      await deleteLoginPasskey(deps, c.req.raw, c.var.actor.user, { secret: passkeySecretOf(body), id: c.req.param('id') ?? '' });
      return c.json({ success: true });
    });
  }

  return app;
}
