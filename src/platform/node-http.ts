import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { handleAppRequest } from '../app';
import { getEnv } from './env';

// Node http adapter: converts IncomingMessage -> Web Request, runs the app,
// and streams the Web Response back. Used by the Vercel function and by the
// local dev server, so both exercise the same code path.

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function toWebRequest(req: IncomingMessage): Request {
  const proto = firstHeader(req.headers['x-forwarded-proto'])?.split(',')[0]?.trim() || 'http';
  // Prefer Host: it is what Vercel routed on and what same-origin checks
  // should compare against; X-Forwarded-Host is only a fallback.
  const host = req.headers.host || firstHeader(req.headers['x-forwarded-host']) || 'localhost';
  const url = new URL(req.url || '/', `${proto}://${host}`);
  // Vercel routes pass the original path as ?__nwpath= (see
  // scripts/build-vercel.ts) in case the function sees the rewritten URL.
  const originalPath = url.searchParams.get('__nwpath');
  if (originalPath !== null) {
    url.searchParams.delete('__nwpath');
    if (originalPath.startsWith('/')) url.pathname = originalPath;
  }

  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else {
      headers.set(name, value);
    }
  }

  const method = (req.method || 'GET').toUpperCase();
  const hasBody = method !== 'GET' && method !== 'HEAD';
  return new Request(url, {
    method,
    headers,
    body: hasBody ? (Readable.toWeb(req) as ReadableStream) : undefined,
    // Required by undici for streaming request bodies.
    duplex: hasBody ? 'half' : undefined,
  } as RequestInit);
}

export async function writeWebResponse(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  if (response.statusText) res.statusMessage = response.statusText;
  const setCookies = response.headers.getSetCookie?.() || [];
  response.headers.forEach((value, name) => {
    if (name.toLowerCase() === 'set-cookie') return;
    res.setHeader(name, value);
  });
  if (setCookies.length) res.setHeader('Set-Cookie', setCookies);

  if (!response.body) {
    res.end();
    return;
  }
  const body = Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);
  await new Promise<void>((resolve, reject) => {
    body.on('error', reject);
    res.on('error', reject);
    res.on('finish', resolve);
    body.pipe(res);
  });
}

export async function handleNodeRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const request = toWebRequest(req);
    const response = await handleAppRequest(request, getEnv());
    await writeWebResponse(res, response);
  } catch (error) {
    console.error('Unhandled request error:', error);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ error: 'Internal server error' }));
    } else {
      res.destroy(error as Error);
    }
  }
}
