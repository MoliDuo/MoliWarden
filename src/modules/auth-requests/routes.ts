import { Hono, type Context } from 'hono';
import { authenticate, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import { pathParam } from '../../http/params';
import { rateLimit } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { answerBody, createBody, type CreateInput } from './schemas';
import {
  answer,
  authRequestById,
  authRequestsJson,
  loginResponse,
  pendingAuthRequests,
  requestAdminApproval,
  requestLogin,
  type RequestingDevice,
} from './service';

const UNKNOWN_DEVICE_TYPE = 14;

// Clients use both prefixes.
const paths = (suffix: string) => [`/api/auth-requests${suffix}`, `/auth-requests${suffix}`];

const originOf = (c: Context) => new URL(c.req.url).host;

// Clients name the device in the body or in their usual headers.
function requestingDevice(c: Context, input: CreateInput): RequestingDevice | null {
  const identifier = input.deviceIdentifier || c.req.header('X-Device-Identifier')?.trim() || c.req.header('Device-Identifier')?.trim();
  if (!identifier) return null;
  const type = Number.parseInt(c.req.header('Device-Type') ?? '', 10);
  return { identifier: identifier.slice(0, 128), type: Number.isInteger(type) && type >= 0 ? type : UNKNOWN_DEVICE_TYPE };
}

export function authRequestRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);
  const sensitive = rateLimit(deps.limiter, 'sensitive');

  app.on('POST', paths(''), sensitive, async (c) => {
    const input = await readJson(c, createBody);
    return c.json(await requestLogin(deps, c.req.raw, input, requestingDevice(c, input)));
  });
  app.on('GET', paths('/:id/response'), sensitive, async (c) =>
    c.json(await loginResponse(deps, originOf(c), pathParam(c, 'id'), (c.req.query('code') ?? '').trim())),
  );

  app.on('GET', paths(''), authed, async (c) => c.json(await authRequestsJson(deps, originOf(c), c.var.actor.user)));
  app.on('GET', paths('/pending'), authed, async (c) => c.json(await pendingAuthRequests(deps, originOf(c), c.var.actor.user)));
  app.on('POST', paths('/admin-request'), authed, async (c) => {
    const input = await readJson(c, createBody);
    return c.json(await requestAdminApproval(deps, c.req.raw, c.var.actor.user, input, requestingDevice(c, input)));
  });
  app.on('GET', paths('/:id'), authed, async (c) =>
    c.json(await authRequestById(deps, originOf(c), c.var.actor.user, pathParam(c, 'id'))),
  );
  app.on('PUT', paths('/:id'), authed, async (c) => {
    const { user, device } = c.var.actor;
    return c.json(await answer(deps, originOf(c), user, device, pathParam(c, 'id'), await readJson(c, answerBody)));
  });

  return app;
}
