import assert from 'node:assert/strict';
import test from 'node:test';

import { corsHeaders, withResponseHeaders } from '../src/http/headers';
import { getConfiguredWebAuthnAllowedOrigins } from '../src/utils/origins';
import { resolveRoute } from '../tests/vercel-emulator';
import { buildVercelConfig } from './vercel-config';

const options = {};

test('only the iframe connector drops anti-framing headers', () => {
  const connectorRequest = new Request('https://vault.example.test/webauthn-connector.html');
  const connector = withResponseHeaders(connectorRequest, new Response('<!doctype html>'), options);
  assert.equal(connector.headers.get('X-Frame-Options'), null);
  assert.doesNotMatch(connector.headers.get('Content-Security-Policy') || '', /frame-ancestors/);
  assert.match(connector.headers.get('Content-Security-Policy') || '', /script-src 'self'/);

  for (const path of ['/', '/webauthn-fallback-connector.html', '/webauthn-mobile-connector.html']) {
    const request = new Request(`https://vault.example.test${path}`);
    const response = withResponseHeaders(request, new Response('<!doctype html>'), options);
    assert.equal(response.headers.get('X-Frame-Options'), 'DENY');
    assert.match(response.headers.get('Content-Security-Policy') || '', /frame-ancestors 'none'/);
  }
});

test('official Bitwarden desktop origin receives credentialed CORS', () => {
  assert.ok(getConfiguredWebAuthnAllowedOrigins({}).includes('bw-desktop-file://bundle'));
  const preflight = corsHeaders(new Request('https://vault.example.test/api/sync', {
    method: 'OPTIONS',
    headers: {
      Origin: 'bw-desktop-file://bundle',
      'Access-Control-Request-Headers': 'authorization, content-type',
    },
  }), options);
  assert.equal(preflight['Access-Control-Allow-Origin'], 'bw-desktop-file://bundle');
  assert.equal(preflight['Access-Control-Allow-Credentials'], 'true');
});

test('Vercel routing serves the official connector .html paths as-is', async () => {
  const config = buildVercelConfig({ hideWebVault: false, cronSchedule: '0 0 * * *' });
  const exists = async (path: string) => (path.endsWith('.html') ? 'static' as const : null);
  for (const path of ['/webauthn-connector.html', '/webauthn-fallback-connector.html', '/webauthn-mobile-connector.html']) {
    const route = await resolveRoute(config as never, path, '', exists);
    assert.deepEqual([route.kind, route.kind === 'static' && route.file], ['static', path]);
    const framable = path === '/webauthn-connector.html';
    assert.equal(route.headers['X-Frame-Options'], framable ? undefined : 'DENY');
    assert.equal(/frame-ancestors/.test(route.headers['Content-Security-Policy'] || ''), !framable);
  }
});
