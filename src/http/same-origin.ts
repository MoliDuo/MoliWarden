import type { MiddlewareHandler } from 'hono';
import { forbidden } from './errors';

// For public routes only the web vault calls: a page on another site must
// not be able to use a visitor's browser, and address, to call them.
export const requireSameOrigin: MiddlewareHandler = async (c, next) => {
  const origin = new URL(c.req.url).origin;
  const claimed = c.req.header('Origin') ?? c.req.header('Referer');
  let sent: string | null = null;
  try {
    sent = claimed ? new URL(claimed).origin : null;
  } catch {
    // An unparseable header counts as another origin.
  }
  if (sent !== origin) throw forbidden('Forbidden origin');
  await next();
};
