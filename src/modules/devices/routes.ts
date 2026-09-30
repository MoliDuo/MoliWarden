import { Hono } from 'hono';
import { authenticate, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { pathParam } from '../../http/params';
import { badRequest, HttpError } from '../../http/errors';
import { consume, requireClientAddress } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { fromBase64url } from '../../platform/crypto';
import {
  keysBody,
  lostTrustBody,
  nameBody,
  pushTokenBody,
  registerBody,
  secretBody,
  trustBody,
  untrustBody,
} from './schemas';
import {
  authorizedDevices,
  clearPushToken,
  deviceById,
  deviceKeys,
  devicesJson,
  forgetRemembered,
  knownDevice,
  registerDevice,
  rememberPermanently,
  removeAllDevices,
  removeDevice,
  renameDevice,
  reportLostTrust,
  setPushToken,
  untrustDevices,
  updateDeviceKeys,
  updateTrust,
} from './service';

// Clients use both prefixes.
const paths = (suffix: string) => [`/api/devices${suffix}`, `/devices${suffix}`];

// Base64url of the email, as official clients send it; older ones sent it as is.
function requestEmail(header: string): string {
  const decoded = fromBase64url(header)?.toString('utf8');
  return (decoded?.includes('@') ? decoded : header).trim().toLowerCase();
}

export function deviceRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);

  // Answers false rather than an error when over the limit, as clients
  // treat any error as "unknown device".
  app.get('/api/devices/knowndevice', async (c) => {
    const limited = await consume(deps.limiter, 'public', requireClientAddress(c.req.raw)).then(
      () => false,
      (error) => {
        if (error instanceof HttpError) return true;
        throw error;
      },
    );
    if (limited) return c.json(false);
    const email = requestEmail(c.req.header('X-Request-Email') ?? '');
    return c.json(await knownDevice(deps, email, (c.req.header('X-Device-Identifier') ?? '').trim()));
  });

  app.on('GET', paths(''), authed, async (c) => c.json(await devicesJson(deps, c.var.actor.user)));
  app.on('POST', paths(''), authed, async (c) =>
    c.json(await registerDevice(deps, c.req.raw, c.var.actor.user, await readJson(c, registerBody))),
  );
  app.on('DELETE', paths(''), authed, async (c) => {
    const { masterPasswordHash } = await readJson(c, secretBody);
    return c.json(await removeAllDevices(deps, c.req.raw, c.var.actor.user, masterPasswordHash));
  });

  app.on('POST', paths('/lost-trust'), authed, async (c) => {
    const identifier =
      (await readJson(c, lostTrustBody)).identifier ||
      c.var.actor.device?.deviceIdentifier ||
      c.req.header('Device-Identifier')?.trim();
    if (!identifier) throw badRequest('Please provide a device identifier');
    await reportLostTrust(deps, c.req.raw, c.var.actor.user, identifier);
    return c.body(null, 200);
  });
  app.on('POST', paths('/update-trust'), authed, async (c) =>
    c.json(await updateTrust(deps, c.var.actor.user, c.var.actor.device, await readJson(c, trustBody))),
  );
  app.on('POST', paths('/untrust'), authed, async (c) =>
    c.json(await untrustDevices(deps, c.req.raw, c.var.actor.user, (await readJson(c, untrustBody)).devices)),
  );

  // Devices that skip two-step login.
  app.on('GET', paths('/authorized'), authed, async (c) => c.json(await authorizedDevices(deps, c.var.actor.user)));
  app.on('DELETE', paths('/authorized'), authed, async (c) => c.json(await forgetRemembered(deps, c.req.raw, c.var.actor.user)));
  app.on('DELETE', paths('/authorized/:identifier'), authed, async (c) =>
    c.json(await forgetRemembered(deps, c.req.raw, c.var.actor.user, pathParam(c, 'identifier'))),
  );
  app.on('POST', paths('/authorized/:identifier/permanent'), authed, async (c) =>
    c.json(await rememberPermanently(deps, c.req.raw, c.var.actor.user, pathParam(c, 'identifier'))),
  );

  app.on('GET', paths('/identifier/:identifier'), authed, async (c) =>
    c.json(await deviceById(deps, c.var.actor.user, pathParam(c, 'identifier'))),
  );
  app.on(['PUT', 'POST'], [...paths('/identifier/:identifier/keys'), ...paths('/:identifier/keys')], authed, async (c) =>
    c.json(await updateDeviceKeys(deps, c.var.actor.user, pathParam(c, 'identifier'), await readJson(c, keysBody))),
  );
  app.on(['PUT', 'POST'], paths('/identifier/:identifier/token'), authed, async (c) => {
    await setPushToken(deps, c.var.actor.user, pathParam(c, 'identifier'), (await readJson(c, pushTokenBody)).pushToken);
    return c.body(null, 200);
  });
  app.on(['PUT', 'POST'], paths('/identifier/:identifier/clear-token'), authed, async (c) => {
    await clearPushToken(deps, c.var.actor.user, pathParam(c, 'identifier'));
    return c.body(null, 200);
  });
  // Web push needs a connection this server cannot hold.
  app.on(['PUT', 'POST'], paths('/identifier/:identifier/web-push-auth'), authed, (c) => c.body(null, 200));

  app.on('GET', paths('/:identifier'), authed, async (c) => c.json(await deviceById(deps, c.var.actor.user, pathParam(c, 'identifier'))));
  app.on('DELETE', paths('/:identifier'), authed, async (c) =>
    c.json(await removeDevice(deps, c.req.raw, c.var.actor.user, pathParam(c, 'identifier'), 'device.delete')),
  );
  app.on(['POST', 'DELETE'], paths('/:identifier/deactivate'), authed, async (c) =>
    c.json(await removeDevice(deps, c.req.raw, c.var.actor.user, pathParam(c, 'identifier'), 'device.deactivate')),
  );
  app.on('PUT', paths('/:identifier/name'), authed, async (c) =>
    c.json(await renameDevice(deps, c.req.raw, c.var.actor.user, pathParam(c, 'identifier'), (await readJson(c, nameBody)).name)),
  );
  app.on('POST', paths('/:identifier/retrieve-keys'), authed, async (c) =>
    c.json(await deviceKeys(deps, c.var.actor.user, pathParam(c, 'identifier'))),
  );

  return app;
}
