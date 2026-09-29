// Local development / self-hosting server: serves the built web vault from
// dist/ and everything else through the same handler the Vercel function uses.
//
//   npm run build && npm run dev:server
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { createNodeHandler } from '../src/main/node';
import { BACKEND_EXACT_PATHS, BACKEND_PATH_PREFIXES } from '../src/web-vault-visibility';

const PORT = Number(process.env.PORT || 8787);
const app = createNodeHandler();
const DIST = join(process.cwd(), 'dist');
const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function isBackendPath(pathname: string): boolean {
  const path = pathname.toLowerCase().replace(/\/+$/, '') || '/';
  if (BACKEND_EXACT_PATHS.has(path)) return true;
  return BACKEND_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

async function tryServeStatic(pathname: string): Promise<{ body: Buffer; type: string } | null> {
  const safe = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
  const candidate = join(DIST, safe);
  if (!candidate.startsWith(DIST)) return null;
  try {
    // Directories fail with EISDIR; no separate stat (avoids a check/use race).
    return { body: await readFile(candidate), type: MIME[extname(candidate)] || 'application/octet-stream' };
  } catch {
    return null;
  }
}

createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  if ((req.method === 'GET' || req.method === 'HEAD') && !isBackendPath(url.pathname) && process.env.HIDE_WEB_VAULT !== '1') {
    const file = (await tryServeStatic(url.pathname)) || (await tryServeStatic('/index.html'));
    if (file) {
      res.writeHead(200, { 'Content-Type': file.type, 'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet' });
      res.end(req.method === 'HEAD' ? undefined : file.body);
      return;
    }
  }
  await app.handler(req, res);
}).listen(PORT, () => {
  console.log(`MoliWarden listening on http://localhost:${PORT}`);
});
