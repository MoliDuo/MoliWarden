import type { IncomingMessage, ServerResponse } from 'node:http';
import { getRequestListener } from '@hono/node-server';
import type { Hono } from 'hono';
import { errorResponse } from '../utils/response';
import { createApp } from './app';
import { readConfig, type Source } from './config';
import { createDeps } from './deps';

// The one way to run the server: the Vercel function, the local dev server
// and the test suites all build a handler here from a set of environment
// variables. Configuration is read on the first request, so a deployment
// with missing settings still answers with an error that names them.

export interface NodeHandler {
  fetch(request: Request): Promise<Response>;
  handler(req: IncomingMessage, res: ServerResponse): Promise<void>;
  dispose(): Promise<void>;
}

// Removes ?__mwpath= and returns its value. Vercel routes pass the original
// path this way (see scripts/vercel-config.ts) in case the function sees the
// rewritten URL. Parsed by hand: URLSearchParams would turn '+' in the path
// into a space and re-encode the other parameters.
function takeOriginalPath(url: URL): string | null {
  const params = url.search.slice(1).split('&');
  const index = params.findIndex((param) => param.startsWith('__mwpath='));
  if (index < 0) return null;
  const [param] = params.splice(index, 1);
  url.search = params.length ? `?${params.join('&')}` : '';
  try {
    return decodeURIComponent(param.slice('__mwpath='.length));
  } catch {
    return null;
  }
}

// The URL the client asked for: the original path, without a trailing slash,
// with the scheme the edge proxy terminated. Always a standard Request: the
// adapter's lightweight request objects cannot be passed to `new Request()`,
// which the handlers not yet ported still do.
export function canonicalRequest(request: Request): Request {
  const url = new URL(request.url);
  const original = takeOriginalPath(url);
  if (original?.startsWith('/')) url.pathname = original;
  if (url.pathname.length > 1) url.pathname = url.pathname.replace(/\/+$/, '');
  const proto = request.headers.get('X-Forwarded-Proto')?.split(',')[0]?.trim();
  if (proto === 'https' || proto === 'http') url.protocol = `${proto}:`;
  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
  return new Request(url, { method: request.method, headers: request.headers, body: hasBody ? request.body : null, duplex: 'half' } as RequestInit);
}

export function createNodeHandler(source: Source = process.env): NodeHandler {
  let runtime: { app: Hono; dispose(): Promise<void> } | null = null;

  function resolve(): Hono | Response {
    if (runtime) return runtime.app;
    try {
      const { deps, dispose } = createDeps(readConfig(source));
      runtime = { app: createApp(deps), dispose };
      return runtime.app;
    } catch (error) {
      const message = `Server configuration error: ${error instanceof Error ? error.message : String(error)}`;
      console.error(message);
      return errorResponse(message, 500);
    }
  }

  async function fetch(request: Request): Promise<Response> {
    const app = resolve();
    if (app instanceof Response) return app;
    return app.fetch(canonicalRequest(request));
  }

  return {
    fetch,
    handler: getRequestListener(fetch, {
      overrideGlobalObjects: false,
      errorHandler: (error) => {
        console.error('Unhandled request error:', error);
        return errorResponse('Internal server error', 500);
      },
    }),
    async dispose() {
      const current = runtime;
      runtime = null;
      await current?.dispose();
    },
  };
}
