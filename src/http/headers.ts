import type { MiddlewareHandler } from 'hono';
import { LIMITS } from '../config/limits';
import {
  isBrowserExtensionOrigin,
  isConfiguredWebAuthnAllowedOrigin,
  isOfficialBitwardenDesktopOrigin,
  normalizeOrigin,
} from '../utils/origins';

// CORS and security headers for every response the function sends. Static
// files served by Vercel get the same security headers from
// scripts/vercel-config.ts.

const CORS_METHODS = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
const CORS_HEADERS = [
  'Content-Type',
  'Authorization',
  'Accept',
  'Device-Type',
  'Device-Identifier',
  'Device-Name',
  'Bitwarden-Client-Name',
  'Bitwarden-Client-Version',
  'Bitwarden-Package-Type',
  'Is-Prerelease',
  'X-Request-Email',
  'X-Device-Identifier',
  'X-Device-Name',
  'X-MoliWarden-Web-Session',
];

// Public, cookie-less resources any site may read.
function isPublicResource(path: string): boolean {
  return (
    path.startsWith('/icons/') ||
    path.startsWith('/fill-assist/') ||
    path === '/v1/assetlinks:check' ||
    path === '/api/v1/assetlinks:check' ||
    path === '/config' ||
    path === '/api/config' ||
    path === '/api/version'
  );
}

export interface CorsOptions {
  // Extra origins (WEBAUTHN_ALLOWED_ORIGINS) trusted besides the official
  // Bitwarden extensions and desktop app.
  allowedOrigins?: string;
}

function allowedOrigin(request: Request, options: CorsOptions): { origin: string; credentials: boolean } | null {
  const url = new URL(request.url);
  const header = request.headers.get('Origin');
  if (!header) return isPublicResource(url.pathname) ? { origin: '*', credentials: false } : null;
  const origin = normalizeOrigin(header);
  if (origin === url.origin) return { origin, credentials: true };
  if (
    (isBrowserExtensionOrigin(origin) || isOfficialBitwardenDesktopOrigin(origin)) &&
    isConfiguredWebAuthnAllowedOrigin({ WEBAUTHN_ALLOWED_ORIGINS: options.allowedOrigins }, origin)
  ) {
    return { origin: origin!, credentials: true };
  }
  return isPublicResource(url.pathname) ? { origin: '*', credentials: false } : null;
}

export function corsHeaders(request: Request, options: CorsOptions): Record<string, string> {
  const requested = String(request.headers.get('Access-Control-Request-Headers') || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': CORS_METHODS,
    'Access-Control-Allow-Headers': Array.from(new Set([...CORS_HEADERS, ...requested])).join(', '),
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Max-Age': String(LIMITS.cors.preflightMaxAgeSeconds),
  };
  const allowed = allowedOrigin(request, options);
  if (allowed) {
    headers['Access-Control-Allow-Origin'] = allowed.origin;
    if (allowed.credentials) headers['Access-Control-Allow-Credentials'] = 'true';
    headers.Vary = 'Origin, Access-Control-Request-Headers';
  }
  return headers;
}

// Official desktop and browser clients render this exact page inside a 40px
// cross-origin iframe. The connector validates its parent before any
// WebAuthn request or postMessage, so only this page may be framed.
export const FRAMEABLE_CONNECTOR_PATH = '/webauthn-connector.html';
export const FRAMEABLE_CONNECTOR_CSP =
  "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";
const DEFAULT_CSP = "frame-ancestors 'none'; img-src 'self' data:";

// Applies the headers to a response; a response's own Content-Security-Policy
// (e.g. the sandbox on website icons) is kept.
export function withResponseHeaders(request: Request, response: Response, options: CorsOptions): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(corsHeaders(request, options))) headers.set(name, value);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (new URL(request.url).pathname === FRAMEABLE_CONNECTOR_PATH) {
    headers.delete('X-Frame-Options');
    headers.set('Content-Security-Policy', FRAMEABLE_CONNECTOR_CSP);
  } else {
    headers.set('X-Frame-Options', 'DENY');
    if (!headers.has('Content-Security-Policy')) headers.set('Content-Security-Policy', DEFAULT_CSP);
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export function responseHeaders(options: CorsOptions): MiddlewareHandler {
  return async (c, next) => {
    await next();
    c.res = withResponseHeaders(c.req.raw, c.res, options);
  };
}

export function preflight(options: CorsOptions): MiddlewareHandler {
  return async (c) => new Response(null, { status: 204, headers: corsHeaders(c.req.raw, options) });
}
