import { Hono } from 'hono';
import { authenticate, callerOf, type AuthedEnv } from '../../http/authenticate';
import type { Deps } from '../../main/deps';
import { sync } from './service';

const isSet = (value: string | undefined) => !!value && /^(1|true|yes)$/i.test(value);

export function syncRoutes(deps: Deps): Hono<AuthedEnv> {
  const app = new Hono<AuthedEnv>();
  app.get('/api/sync', authenticate(deps), async (c) =>
    c.json(
      await sync(deps, callerOf(c), {
        excludeDomains: isSet(c.req.query('excludeDomains')),
        excludeSends: isSet(c.req.query('excludeSends')),
      }),
      200,
      { 'Cache-Control': 'no-store' },
    ),
  );
  return app;
}
