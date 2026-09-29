import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';

// Node http adapter: converts IncomingMessage -> Web Request and streams a
// Web Response back (see src/main/node.ts).

function firstHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

// Removes ?__mwpath= from url and returns its value. Parsed by hand rather
// than with URLSearchParams, which would turn '+' in the path into a space
// and re-encode the remaining query parameters.
function takeOriginalPathParam(url: URL): string | null {
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

export function toWebRequest(req: IncomingMessage): Request {
  const proto = firstHeader(req.headers['x-forwarded-proto'])?.split(',')[0]?.trim() || 'http';
  // Prefer Host: it is what Vercel routed on and what same-origin checks
  // should compare against; X-Forwarded-Host is only a fallback.
  const host = req.headers.host || firstHeader(req.headers['x-forwarded-host']) || 'localhost';
  const url = new URL(req.url || '/', `${proto}://${host}`);
  // Vercel routes pass the original path as ?__mwpath= (see
  // scripts/build-vercel.ts) in case the function sees the rewritten URL.
  const originalPath = takeOriginalPathParam(url);
  if (originalPath !== null && originalPath.startsWith('/')) url.pathname = originalPath;

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
