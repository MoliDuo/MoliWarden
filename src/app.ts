import { Env } from './types';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { applyCors, errorResponse, jsonResponse } from './utils/response';
import { runScheduledBackupIfDue } from './handlers/backup';

// Platform-neutral request handler. src/platform/node-http.ts adapts it to
// Node's http module (Vercel Functions and the local dev server).

const CRON_PATH = '/api/internal/cron';

function normalizeRequestUrl(request: Request): Request {
  const url = new URL(request.url);
  const normalizedPathname = url.pathname.length <= 1 ? url.pathname : url.pathname.replace(/\/+$/, '');
  if (normalizedPathname === url.pathname) return request;

  url.pathname = normalizedPathname;
  return new Request(url.toString(), request);
}

// Schema bootstrap runs once per database; a failure is retried on the next
// request.
const dbInit = new WeakMap<Env['DB'], Promise<void>>();

async function ensureDatabaseInitialized(env: Env): Promise<string | null> {
  let pending = dbInit.get(env.DB);
  if (!pending) {
    pending = new StorageService(env.DB).initializeDatabase();
    dbInit.set(env.DB, pending);
  }
  try {
    await pending;
    return null;
  } catch (error) {
    if (dbInit.get(env.DB) === pending) dbInit.delete(env.DB);
    console.error('Failed to initialize database:', error);
    return error instanceof Error ? error.message : 'Unknown database initialization error';
  }
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  return diff === 0;
}

async function handleCron(request: Request, env: Env): Promise<Response> {
  const secret = String(env.CRON_SECRET || '').trim();
  const provided = String(request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim();
  if (!secret || !provided || !constantTimeEqual(secret, provided)) {
    return errorResponse('Unauthorized', 401);
  }
  await runScheduledBackupIfDue(env);
  return jsonResponse({ ok: true });
}

export async function handleAppRequest(request: Request, env: Env): Promise<Response> {
  const normalizedRequest = normalizeRequestUrl(request);

  const dbInitError = await ensureDatabaseInitialized(env);
  if (dbInitError) {
    // Log full error server-side, return generic message to client.
    console.error('DB init error (not forwarded to client):', dbInitError);
    const resp = jsonResponse(
      {
        error: 'Database not initialized',
        error_description: 'Database initialization failed. Check server logs for details.',
        ErrorModel: {
          Message: 'Database unavailable. Check DATABASE_URL and the function logs.',
          Object: 'error',
        },
      },
      500
    );
    return applyCors(normalizedRequest, resp, env);
  }

  if (new URL(normalizedRequest.url).pathname === CRON_PATH && normalizedRequest.method === 'GET') {
    return handleCron(normalizedRequest, env);
  }

  const resp = await handleRequest(normalizedRequest, env);
  return applyCors(normalizedRequest, resp, env);
}
