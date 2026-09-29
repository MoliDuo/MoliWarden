import { Hono, type ErrorHandler, type MiddlewareHandler } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { LIMITS } from '../config/limits';
import { runScheduledBackupIfDue } from '../handlers/backup';
import { HttpError, IdentityError, misconfigured, payloadTooLarge, unauthorized } from '../http/errors';
import { preflight, responseHeaders } from '../http/headers';
import { accountRoutes } from '../modules/accounts/routes';
import { attachmentRoutes } from '../modules/attachments/routes';
import { deleteExpiredAuthRequests } from '../modules/auth-requests/repo';
import { authRequestRoutes } from '../modules/auth-requests/routes';
import { cipherRoutes } from '../modules/ciphers/routes';
import { deviceRoutes } from '../modules/devices/routes';
import { domainRoutes } from '../modules/domains/routes';
import { folderRoutes } from '../modules/folders/routes';
import { iconRoutes } from '../modules/icons/routes';
import { identityRoutes } from '../modules/identity/routes';
import { metaRoutes } from '../modules/meta/routes';
import { organizationRoutes } from '../modules/organizations/routes';
import { passkeyRoutes } from '../modules/passkeys/routes';
import { sendRoutes } from '../modules/sends/routes';
import { syncRoutes } from '../modules/sync/routes';
import { twoFactorRoutes } from '../modules/two-factor/routes';
import { constantTimeEqual } from '../platform/crypto';
import { BlobStoreError } from '../platform/blob';
import { handleRequest as handleLegacyRequest } from '../router';
import { StorageService } from '../services/storage';
import type { Deps } from './deps';

// Routes whose bodies are file contents; they enforce the upload limit
// themselves.
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
    onError: () => {
      throw payloadTooLarge();
    },
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
      throw new HttpError(500, 'Database unavailable. Check DATABASE_URL and the function logs.');
    }
    await next();
  };
}

// Everything past this point signs or verifies tokens.
function requireJwtSecret(deps: Deps): MiddlewareHandler {
  return async (_c, next) => {
    if (deps.config.jwtSecretProblem) throw misconfigured('JWT_SECRET is not set or too weak');
    await next();
  };
}

export const handleError: ErrorHandler = (error, c) => {
  if (error instanceof HttpError) return c.json(error.body, error.status, error.headers);
  if (error instanceof IdentityError) {
    return c.json(error.body, error.status, { ...error.headers, 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  }
  if (error instanceof BlobStoreError) {
    console.error('File storage error:', error.detail || error.message);
    return c.json(new HttpError(500, error.message).body, 500);
  }
  console.error('Request error:', error);
  return c.json(new HttpError(500, 'Internal server error').body, 500);
};

export function createApp(deps: Deps): Hono {
  const app = new Hono({ strict: false });
  const cors = { allowedOrigins: deps.config.webauthn.allowedOrigins };

  app.use(responseHeaders(cors));
  app.options('*', preflight(cors));
  app.use(limitRequestBody());
  app.use(ensureDatabase(deps));

  app.route('/', metaRoutes(deps));
  app.route('/', iconRoutes(deps));

  // Vercel Cron sends "Authorization: Bearer <CRON_SECRET>".
  app.get('/api/internal/cron', async (c) => {
    const secret = deps.config.cronSecret;
    const provided = (c.req.header('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
    if (!secret || !provided || !constantTimeEqual(secret, provided)) throw unauthorized();
    await Promise.all([runScheduledBackupIfDue(deps.legacyEnv), deleteExpiredAuthRequests(deps.db)]);
    return c.json({ ok: true });
  });

  // Routes registered before this line answer on any configuration.
  app.use(requireJwtSecret(deps));
  app.route('/', identityRoutes(deps));
  app.route('/', twoFactorRoutes(deps));
  app.route('/', passkeyRoutes(deps));
  app.route('/', accountRoutes(deps));
  app.route('/', deviceRoutes(deps));
  app.route('/', authRequestRoutes(deps));
  app.route('/', syncRoutes(deps));
  app.route('/', folderRoutes(deps));
  app.route('/', attachmentRoutes(deps));
  app.route('/', cipherRoutes(deps));
  app.route('/', domainRoutes(deps));
  app.route('/', organizationRoutes(deps));
  app.route('/', sendRoutes(deps));

  // Routes not yet ported to src/modules.
  app.all('*', (c) => handleLegacyRequest(c.req.raw, deps.legacyEnv));

  app.onError(handleError);
  return app;
}
