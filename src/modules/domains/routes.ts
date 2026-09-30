import { Hono } from 'hono';
import { authenticate, callerOf, type AuthedEnv } from '../../http/authenticate';
import { readJson } from '../../http/body';
import type { Deps } from '../../main/deps';
import { domainsBody } from './schemas';
import { domainsJson, updateDomains } from './service';

const PATHS = ['/api/settings/domains', '/settings/domains'];

export function domainRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  const authed = authenticate(deps);
  app.on('GET', PATHS, authed, async (c) => c.json(await domainsJson(deps.db, c.var.actor.user.id)));
  app.on(['PUT', 'POST'], PATHS, authed, async (c) => c.json(await updateDomains(deps, callerOf(c), await readJson(c, domainsBody))));
  return app;
}
