import { Hono, type ErrorHandler, type MiddlewareHandler } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { LIMITS } from '../config/limits';
import { HttpError, IdentityError, misconfigured, notFound, payloadTooLarge } from '../http/errors';
import { preflight, responseHeaders } from '../http/headers';
import { accountRoutes } from '../modules/accounts/routes';
import { adminRoutes } from '../modules/admin/routes';
import { attachmentRoutes } from '../modules/attachments/routes';
import { auditRoutes } from '../modules/audit/routes';
import { backupRoutes } from '../modules/backup/routes';
import { authRequestRoutes } from '../modules/auth-requests/routes';
import { cipherRoutes } from '../modules/ciphers/routes';
import { cronRoutes } from '../modules/cron/routes';
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
import { SecretBoxError } from '../platform/crypto';
import { BlobStoreError } from '../platform/blob';
import { migrateToLatest, schemaState } from '../platform/db/migrate';
import { secretProblem } from './config';
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

// Brings the schema up to date once per process; a failure is retried on
// the next request. Tables of an earlier version are never converted here:
// that is scripts/migrate-legacy.ts, run by the operator.
function ensureMigrated(deps: Deps): MiddlewareHandler {
  let ready: Promise<void> | null = null;
  const migrate = async () => {
    const state = await schemaState(deps.db);
    if (state === 'legacy') throw LEGACY_DATABASE;
    if (state === 'outdated') await migrateToLatest(deps.pool);
  };
  return async (_c, next) => {
    const pending = (ready ??= migrate());
    try {
      await pending;
    } catch (error) {
      if (ready === pending) ready = null;
      if (error === LEGACY_DATABASE) throw error;
      console.error('Database migration failed:', error);
      throw new HttpError(500, 'Database unavailable. Check DATABASE_URL and the function logs.');
    }
    await next();
  };
}

const LEGACY_DATABASE = new HttpError(
  503,
  'The database holds the data of an earlier MoliWarden version. Run `npm run db:migrate-legacy` against it (see the README), then reload.',
);

// Everything past this point signs tokens or keeps secrets.
function requireSecrets(deps: Deps): MiddlewareHandler {
  return async (_c, next) => {
    const problem = secretProblem(deps.config);
    if (problem) throw misconfigured(`${problem.name} is not set or too weak`);
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
  if (error instanceof SecretBoxError) {
    console.error('Stored secret unreadable:', error.message);
    return c.json(misconfigured('a stored secret cannot be decrypted. Was ENCRYPTION_KEY changed?').body, 500);
  }
  // An id that is not a UUID gets this far only where no schema checks it.
  if ((error as { code?: unknown }).code === INVALID_TEXT_REPRESENTATION) {
    return c.json(new HttpError(400, 'Invalid identifier').body, 400);
  }
  console.error('Request error:', error);
  return c.json(new HttpError(500, 'Internal server error').body, 500);
};

const INVALID_TEXT_REPRESENTATION = '22P02';

export function createApp(deps: Deps): Hono {
  const app = new Hono({ strict: false });
  const cors = { allowedOrigins: deps.config.webauthn.allowedOrigins };

  app.use(responseHeaders(cors));
  app.options('*', preflight(cors));
  app.use(limitRequestBody());
  app.use(ensureMigrated(deps));

  app.route('/', metaRoutes(deps));
  app.route('/', iconRoutes(deps));

  // Routes registered before this line answer on any configuration.
  app.use(requireSecrets(deps));

  app.route('/', cronRoutes(deps));
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
  app.route('/', adminRoutes(deps));
  app.route('/', auditRoutes(deps));
  app.route('/', backupRoutes(deps));

  app.notFound((c) => c.json(notFound('Route not found').body, 404));

  app.onError(handleError);
  return app;
}
