// Serves a Vercel Build Output API v3 bundle (.vercel/output) the way Vercel
// does, closely enough to catch deployment mistakes before deploying:
//   - config.json routes: src/dest/$n, headers + continue, status, the
//     filesystem phase and the SPA fallback after it
//   - the function is loaded from its own directory, like Vercel's Node
//     launcher (copy the output outside the repo so node_modules can't mask
//     missing bundled dependencies)
//   - 4.5 MB request body limit, x-forwarded-* / x-vercel-* headers,
//     waitUntil() via the @vercel/request-context global, Vercel Cron calls
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { Readable } from 'node:stream';
import { pathToFileURL } from 'node:url';

export const VERCEL_BODY_LIMIT_BYTES = 4.5 * 1024 * 1024;

interface Route {
  src?: string;
  dest?: string;
  headers?: Record<string, string>;
  continue?: boolean;
  status?: number;
  handle?: string;
}

interface OutputConfig {
  version: number;
  routes: Route[];
  crons?: Array<{ path: string; schedule: string }>;
}

export type RouteResult =
  | { kind: 'static'; file: string; headers: Record<string, string>; status: number }
  | { kind: 'function'; name: string; url: string; headers: Record<string, string> }
  | { kind: 'status'; status: number; headers: Record<string, string> };

type NodeHandler = (req: IncomingMessage, res: ServerResponse) => unknown;

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

function substitute(dest: string, match: RegExpExecArray): string {
  return dest.replace(/\$(\d+)/g, (_, index: string) => match[Number(index)] ?? '');
}

// `vercel build` rewrites config.json and moves header-only `continue`
// routes of the first phase ahead of the others; mirror that so tests see
// the routing that actually gets deployed.
function hoistHeaderRoutes(routes: Route[]): Route[] {
  const firstHandle = routes.findIndex((route) => route.handle);
  const main = firstHandle < 0 ? routes : routes.slice(0, firstHandle);
  const rest = firstHandle < 0 ? [] : routes.slice(firstHandle);
  const isHeaderOnly = (route: Route) => !!route.continue && !!route.headers && !route.dest && !route.status;
  return [...main.filter(isHeaderOnly), ...main.filter((route) => !isHeaderOnly(route)), ...rest];
}

// Pure routing: resolves a path against config.json. `exists` reports
// whether a static file or function exists for a filesystem path.
export async function resolveRoute(
  config: OutputConfig,
  pathname: string,
  search: string,
  exists: (path: string) => Promise<'static' | 'function' | null>
): Promise<RouteResult> {
  const headers: Record<string, string> = {};
  let path = pathname;
  let query = new URLSearchParams(search);
  let afterFilesystem = false;

  const resolveTarget = async (target: string): Promise<RouteResult> => {
    const kind = await exists(target);
    if (kind === 'function') {
      const qs = query.toString();
      return { kind: 'function', name: target.replace(/^\//, ''), url: `${target}${qs ? `?${qs}` : ''}`, headers };
    }
    if (kind === 'static') return { kind: 'static', file: target, headers, status: 200 };
    return { kind: 'status', status: 404, headers };
  };

  // Routes after a `handle` marker belong to that phase. Only the main phase
  // and the one after the filesystem check apply to a normal request; others
  // (e.g. the `error` phase `vercel build` adds) run only in special cases.
  let phase: string | null = null;
  for (const route of hoistHeaderRoutes(config.routes)) {
    if (route.handle) {
      phase = route.handle;
      if (route.handle === 'filesystem') {
        const kind = await exists(path);
        if (kind) return resolveTarget(path);
        afterFilesystem = true;
      }
      continue;
    }
    if (phase !== null && phase !== 'filesystem') continue;
    if (!route.src) continue;
    const match = new RegExp(route.src).exec(path);
    if (!match) continue;
    Object.assign(headers, route.headers || {});
    if (route.dest) {
      const dest = new URL(substitute(route.dest, match), 'http://route.local');
      // Vercel merges the original query into the destination's.
      const merged = new URLSearchParams(dest.search);
      for (const [key, value] of query) if (!merged.has(key)) merged.append(key, value);
      path = dest.pathname;
      query = merged;
    }
    if (route.status && !route.dest) return { kind: 'status', status: route.status, headers };
    if (route.continue) continue;
    if (route.dest || afterFilesystem) return resolveTarget(path);
  }
  return resolveTarget(path);
}

export interface VercelEmulator {
  baseUrl: string;
  config: OutputConfig;
  // Background work registered through waitUntil(), awaited like Vercel does
  // before freezing the instance.
  drainBackgroundWork(): Promise<void>;
  runCrons(): Promise<Response[]>;
  close(): Promise<void>;
}

export async function startVercelEmulator(outputDir: string, env: Record<string, string>): Promise<VercelEmulator> {
  const config = JSON.parse(await readFile(join(outputDir, 'config.json'), 'utf8')) as OutputConfig;
  Object.assign(process.env, { VERCEL: '1', VERCEL_ENV: 'production', VERCEL_REGION: 'iad1' }, env);

  const pending = new Set<Promise<unknown>>();
  const contextSymbol = Symbol.for('@vercel/request-context');
  (globalThis as Record<symbol, unknown>)[contextSymbol] = {
    get: () => ({
      waitUntil(promise: Promise<unknown>) {
        const tracked = Promise.resolve(promise).catch((error) => console.error('waitUntil task failed:', error));
        pending.add(tracked);
        void tracked.finally(() => pending.delete(tracked));
      },
    }),
  };

  const functions = new Map<string, NodeHandler>();
  const loadFunction = async (name: string): Promise<NodeHandler> => {
    const cached = functions.get(name);
    if (cached) return cached;
    const funcDir = join(outputDir, 'functions', `${name}.func`);
    const vcConfig = JSON.parse(await readFile(join(funcDir, '.vc-config.json'), 'utf8'));
    if (vcConfig.launcherType !== 'Nodejs') throw new Error(`unsupported launcher ${vcConfig.launcherType}`);
    const mod = await import(pathToFileURL(join(funcDir, vcConfig.handler)).href);
    const handler = (mod.default?.default || mod.default) as NodeHandler;
    if (typeof handler !== 'function') throw new Error(`${name}.func does not export a default handler`);
    functions.set(name, handler);
    return handler;
  };

  const exists = async (path: string): Promise<'static' | 'function' | null> => {
    const clean = normalize(decodeURIComponent(path)).replace(/^(\.\.[/\\])+/, '');
    try {
      await stat(join(outputDir, 'functions', `${clean.replace(/^\//, '')}.func`, '.vc-config.json'));
      return 'function';
    } catch {
      // not a function
    }
    const file = clean === '/' ? '/index.html' : clean;
    try {
      if ((await stat(join(outputDir, 'static', file))).isFile()) return 'static';
    } catch {
      // not a file
    }
    return null;
  };

  const server: Server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://localhost');
      const result = await resolveRoute(config, url.pathname, url.search, exists);
      for (const [name, value] of Object.entries(result.headers)) res.setHeader(name, value);

      if (result.kind === 'status') {
        res.statusCode = result.status;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end(result.status === 404 ? 'The page could not be found\n\nNOT_FOUND\n' : '');
        return;
      }
      if (result.kind === 'static') {
        const file = result.file === '/' ? '/index.html' : result.file;
        const body = await readFile(join(outputDir, 'static', decodeURIComponent(file)));
        res.statusCode = 200;
        res.setHeader('Content-Type', MIME[extname(file)] || 'application/octet-stream');
        res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
        res.end(req.method === 'HEAD' ? undefined : body);
        return;
      }

      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > VERCEL_BODY_LIMIT_BYTES) {
          res.statusCode = 413;
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          res.end('Request Entity Too Large\n\nFUNCTION_PAYLOAD_TOO_LARGE\n');
          return;
        }
        chunks.push(chunk);
      }
      const forwardedFor = '203.0.113.7';
      const upstream = Object.assign(Readable.from(chunks.length ? [Buffer.concat(chunks)] : []), {
        method: req.method,
        url: result.url,
        headers: {
          ...req.headers,
          'x-forwarded-proto': 'https',
          'x-forwarded-host': req.headers.host,
          'x-forwarded-for': forwardedFor,
          'x-real-ip': forwardedFor,
          'x-vercel-forwarded-for': forwardedFor,
          'x-vercel-ip-country': 'NL',
          'x-vercel-id': `iad1::${Date.now()}`,
        },
      }) as unknown as IncomingMessage;
      const handler = await loadFunction(result.name);
      await handler(upstream, res);
    } catch (error) {
      console.error('emulator error:', error);
      if (!res.headersSent) {
        res.statusCode = 502;
        res.end('FUNCTION_INVOCATION_FAILED');
      } else {
        res.destroy();
      }
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    config,
    async drainBackgroundWork() {
      while (pending.size) await Promise.all([...pending]);
    },
    async runCrons() {
      const responses: Response[] = [];
      for (const cron of config.crons || []) {
        const headers: Record<string, string> = { 'User-Agent': 'vercel-cron/1.0' };
        if (process.env.CRON_SECRET) headers.Authorization = `Bearer ${process.env.CRON_SECRET}`;
        responses.push(await fetch(`${baseUrl}${cron.path}`, { headers }));
      }
      return responses;
    },
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
