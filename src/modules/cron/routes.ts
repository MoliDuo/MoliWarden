import { Hono } from 'hono';
import { unauthorized } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { constantTimeEqual } from '../../platform/crypto';
import { runCron } from './service';

export function cronRoutes(deps: Deps): Hono {
  const app = new Hono();

  // Vercel Cron sends "Authorization: Bearer <CRON_SECRET>".
  app.get('/api/internal/cron', async (c) => {
    const secret = deps.config.cronSecret;
    const provided = (c.req.header('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!secret || !provided || !constantTimeEqual(secret, provided)) throw unauthorized();
    return c.json({ object: 'cron', ...(await runCron(deps)) });
  });

  return app;
}
