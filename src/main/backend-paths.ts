// Paths the function answers; everything else is the web vault's static
// files. Used by the Vercel build and the dev server to route requests.

export const BACKEND_PATH_PREFIXES = [
  '/api',
  '/identity',
  '/icons',
  '/fill-assist',
  '/notifications',
  '/.well-known',
  // Aliases older Bitwarden clients still call.
  '/devices',
  '/auth-requests',
  '/webauthn',
] as const;

export const BACKEND_EXACT_PATHS = new Set([
  '/v1/assetlinks:check',
  '/web-bootstrap',
  '/config',
  '/accounts/kdf',
  '/settings/domains',
]);
