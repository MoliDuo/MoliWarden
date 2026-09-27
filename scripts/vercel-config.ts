// Routing for the Vercel Build Output API bundle (.vercel/output/config.json).
// Kept separate from build-vercel.ts so tests can check it without building.
import { BACKEND_EXACT_PATHS, BACKEND_PATH_PREFIXES } from '../src/web-vault-visibility';

export interface VercelConfigOptions {
  hideWebVault: boolean;
  cronSchedule: string;
}

export const WEBAUTHN_FRAME_CONNECTOR_CSP =
  "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";

// Static files are served by Vercel without passing through the function, so
// the headers applyCors() adds to API responses are declared here instead.
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
      { src: backendRouteSource(), dest: '/index?__nwpath=$1' },
      // Official clients frame this exact page; everything else must not be framed.
      {
        src: '^/webauthn-connector\\.html$',
        headers: { ...STATIC_SECURITY_HEADERS, 'Content-Security-Policy': WEBAUTHN_FRAME_CONNECTOR_CSP },
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
