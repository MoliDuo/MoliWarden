import { Env } from './types';
import { handleRequest } from './router';
import { StorageService } from './services/storage';
import { applyCors, errorResponse, jsonResponse } from './utils/response';
import { runScheduledBackupIfDue } from './handlers/backup';

// Platform-neutral request handler. src/platform/node-http.ts adapts it to
// Node's http module (Vercel Functions and the local dev server).

let dbInitialized = false;
let dbInitError: string | null = null;
let dbInitPromise: Promise<void> | null = null;

const CRON_PATH = '/api/internal/cron';

function normalizeRequestUrl(request: Request): Request {
  const url = new URL(request.url);
  const normalizedPathname = url.pathname.length <= 1 ? url.pathname : url.pathname.replace(/\/+$/, '');
  if (normalizedPathname === url.pathname) return request;

  url.pathname = normalizedPathname;
  return new Request(url.toString(), request);
}

async function ensureDatabaseInitialized(env: Env): Promise<void> {
  if (dbInitialized) return;

  if (!dbInitPromise) {
    dbInitPromise = (async () => {
      const storage = new StorageService(env.DB);
      await storage.initializeDatabase();
      dbInitialized = true;
      dbInitError = null;
    })()
      .catch((error: unknown) => {
        console.error('Failed to initialize database:', error);
        dbInitError = error instanceof Error ? error.message : 'Unknown database initialization error';
      })
      .finally(() => {
        dbInitPromise = null;
      });
  }

  await dbInitPromise;
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

  await ensureDatabaseInitialized(env);
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
