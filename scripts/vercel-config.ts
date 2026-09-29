// Routing for the Vercel Build Output API bundle (.vercel/output/config.json).
// Kept separate from build-vercel.ts so tests can check it without building.
import { FRAMEABLE_CONNECTOR_CSP } from '../src/http/headers';
import { BACKEND_EXACT_PATHS, BACKEND_PATH_PREFIXES } from '../src/web-vault-visibility';

// The single function serving every API route (.vercel/output/functions/<name>.func).
export const FUNCTION_NAME = '_moliwarden';

export interface VercelConfigOptions {
  hideWebVault: boolean;
  cronSchedule: string;
}


// Static files are served by Vercel without passing through the function, so
// the headers src/http/headers.ts adds to API responses are declared here instead.
const STATIC_SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function backendPathPattern(): string {
  const prefixPattern = BACKEND_PATH_PREFIXES.map((prefix) => escapeRegex(prefix.slice(1))).join('|');
  const exactPattern = Array.from(BACKEND_EXACT_PATHS).map(escapeRegex).join('|');
  return `(/(?:${prefixPattern})(?:/.*)?|${exactPattern})/?$`;
}

export function backendRouteSource(): string {
  return `^${backendPathPattern()}`;
}

export function buildVercelConfig(options: VercelConfigOptions): Record<string, unknown> {
  return {
    version: 3,
    routes: [
      {
        src: '^/(.*)$',
        headers: { 'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet' },
        continue: true,
      },
      { src: backendRouteSource(), dest: `/${FUNCTION_NAME}?__mwpath=$1` },
      // Official clients frame this exact page; everything else must not be framed.
      {
        src: '^/webauthn-connector\\.html$',
        headers: { ...STATIC_SECURITY_HEADERS, 'Content-Security-Policy': FRAMEABLE_CONNECTOR_CSP },
        continue: true,
      },
      // `vercel build` moves header-only routes ahead of the API route, so
      // these must exclude API paths themselves; API responses carry their
      // own headers (e.g. the sandbox CSP on website icons).
      {
        src: `^(?!${backendPathPattern()})(?!/webauthn-connector\\.html$).*$`,
        headers: {
          ...STATIC_SECURITY_HEADERS,
          'X-Frame-Options': 'DENY',
          'Content-Security-Policy': "frame-ancestors 'none'; img-src 'self' data:",
        },
        continue: true,
      },
      { handle: 'filesystem' },
      ...(options.hideWebVault
        ? [{ src: '^/(.*)$', status: 404 }]
        : [
            { src: '^/assets/(.*)$', status: 404 },
            { src: '^/(.*)$', dest: '/index.html' },
          ]),
    ],
    crons: [{ path: '/api/internal/cron', schedule: options.cronSchedule }],
  };
}
