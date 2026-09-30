import { Hono } from 'hono';
import { rateLimit } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { findIcon, GLOBE_ICON, ICON_CACHE_CONTROL, normalizeHost } from './service';

export function iconRoutes(deps: Deps): Hono {
  const app = new Hono();

  app.get('/icons/:host/icon.png', rateLimit(deps.limiter, 'icons'), async (c) => {
    const host = normalizeHost(c.req.param('host'));
    const icon = host ? await findIcon(deps.config.iconSource, host) : null;
    if (icon) {
      return c.body(icon.body, 200, {
        'Content-Type': icon.contentType,
        'Cache-Control': ICON_CACHE_CONTROL,
        'Content-Security-Policy': "default-src 'none'; img-src 'self' data:; sandbox",
      });
    }
    if (c.req.query('fallback') === '404') return c.body(null, 404, { 'Cache-Control': 'public, max-age=300' });
    return c.body(GLOBE_ICON, 200, { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': ICON_CACHE_CONTROL });
  });

  return app;
}
