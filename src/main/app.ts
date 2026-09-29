import { Hono, type MiddlewareHandler } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { LIMITS } from '../config/limits';
import { runScheduledBackupIfDue } from '../handlers/backup';
import { preflight, responseHeaders } from '../http/headers';
import { constantTimeEqual } from '../platform/crypto';
import { handleRequest as handleLegacyRequest } from '../router';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import type { Deps } from './deps';

// Routes whose bodies are file contents streamed to storage; their handlers
// enforce the upload limits themselves.
function isFileUpload(path: string): boolean {
  return (
    /^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path) ||
    /^\/api\/sends\/[a-f0-9-]+\/file\/[a-f0-9-]+$/i.test(path) ||
    path === '/api/admin/backup/import'
  );
}

function limitRequestBody(): MiddlewareHandler {
  const limit = bodyLimit({
    maxSize: LIMITS.request.maxBodyBytes,
    onError: () => errorResponse('Request body too large', 413),
  });
  return (c, next) => (isFileUpload(c.req.path) ? next() : limit(c, next));
}

// Creates or upgrades the schema once per process; a failure is retried on
// the next request.
function ensureDatabase(deps: Deps): MiddlewareHandler {
  let ready: Promise<void> | null = null;
  return async (_c, next) => {
    const pending = (ready ??= new StorageService(deps.legacyEnv.DB).initializeDatabase());
    try {
      await pending;
    } catch (error) {
      if (ready === pending) ready = null;
      console.error('Database initialization failed:', error);
      return jsonResponse(
        {
          error: 'Database not initialized',
          error_description: 'Database initialization failed. Check server logs for details.',
          ErrorModel: { Message: 'Database unavailable. Check DATABASE_URL and the function logs.', Object: 'error' },
        },
        500,
      );
    }
    await next();
  };
}

export function createApp(deps: Deps): Hono {
  const app = new Hono({ strict: false });
  const cors = { allowedOrigins: deps.config.webauthn.allowedOrigins };

  app.use(responseHeaders(cors));
  app.options('*', preflight(cors));
  app.use(limitRequestBody());
  app.use(ensureDatabase(deps));

  // Vercel Cron sends "Authorization: Bearer <CRON_SECRET>".
  app.get('/api/internal/cron', async (c) => {
    const secret = deps.config.cronSecret;
    const provided = (c.req.header('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!secret || !provided || !constantTimeEqual(secret, provided)) return errorResponse('Unauthorized', 401);
    await runScheduledBackupIfDue(deps.legacyEnv);
    return c.json({ ok: true });
  });

  // Routes not yet ported to src/modules.
  app.all('*', (c) => handleLegacyRequest(c.req.raw, deps.legacyEnv));

  app.onError((error) => {
    console.error('Request error:', error);
    return errorResponse('Internal server error', 500);
  });
  return app;
}
