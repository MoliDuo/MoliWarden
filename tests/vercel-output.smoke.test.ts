// Smoke test of the deployable artifact: runs .vercel/output (from
// `npm run build:vercel`) under tests/vercel-emulator.ts, copied outside the
// repository so the function can only use what was bundled into it.
//
//   npm run test:smoke        (builds first)
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  Client,
  cipherPayload,
  ensureBucket,
  removeBucket,
  fakeEncString,
  resetDatabase,
  testServerEnv,
  TEST_DATABASE_URL,
  type Session,
} from './helpers';
import { FUNCTION_NAME } from '../scripts/vercel-config';
import { resolveRoute, startVercelEmulator, VERCEL_BODY_LIMIT_BYTES, type VercelEmulator } from './vercel-emulator';

const OUTPUT_DIR = join(process.cwd(), '.vercel', 'output');

let workDir: string;
let vercel: VercelEmulator;
let client: Client;
let alice: Session;

const bucket = `mw-smoke-${process.pid}`;

before(async () => {
  try {
    await stat(join(OUTPUT_DIR, 'config.json'));
  } catch {
    throw new Error('No .vercel/output found; run `npm run build:vercel` first (or use `npm run test:smoke`).');
  }
  workDir = await mkdtemp(join(tmpdir(), 'moliwarden-smoke-'));
  await cp(OUTPUT_DIR, workDir, { recursive: true });

  await resetDatabase();
  await ensureBucket(bucket);
  vercel = await startVercelEmulator(workDir, {
    ...testServerEnv(bucket),
    DATABASE_URL: TEST_DATABASE_URL,
    VERCEL_URL: 'moliwarden-smoke.vercel.app',
  });
  client = new Client(vercel.baseUrl, `https://${new URL(vercel.baseUrl).host}`);
});

after(async () => {
  await vercel?.close();
  await removeBucket(bucket).catch(() => undefined);
  if (workDir) await rm(workDir, { recursive: true, force: true });
  // The bundled function owns its own pg pool; nothing else keeps the loop alive.
  setTimeout(() => process.exit(process.exitCode ?? 0), 100).unref();
});

function get(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${vercel.baseUrl}${path}`, { redirect: 'manual', ...init });
}

// Server-built URLs carry the public https origin; replay them locally.
function local(url: string): string {
  const parsed = new URL(url);
  return parsed.pathname + parsed.search;
}

test('build output is complete', async () => {
  const vc = JSON.parse(await readFile(join(workDir, `functions/${FUNCTION_NAME}.func/.vc-config.json`), 'utf8'));
  assert.match(vc.runtime, /^nodejs\d+\.x$/);
  await stat(join(workDir, `functions/${FUNCTION_NAME}.func`, vc.handler));
  await stat(join(workDir, 'static/index.html'));
  assert.equal(vercel.config.version, 3);
  assert.ok(vercel.config.crons?.some((cron) => cron.path === '/api/internal/cron'));
});

test('concurrent cold-start requests all succeed while the schema is created', async () => {
  const responses = await Promise.all(
    Array.from({ length: 12 }, (_, i) =>
      i % 2
        ? get('/api/config')
        : get('/identity/accounts/prelogin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: `nobody${i}@example.com` }),
          })
    )
  );
  for (const response of responses) {
    assert.equal(response.status, 200, await response.text());
  }
});

test('web vault is served statically with security headers and SPA fallback', async () => {
  const index = await get('/');
  assert.equal(index.status, 200);
  assert.match(index.headers.get('content-type') || '', /text\/html/);
  const html = await index.text();
  assert.match(html, /<div id="root"|<script/);
  assert.equal(index.headers.get('x-frame-options'), 'DENY');
  assert.match(index.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  assert.equal(index.headers.get('x-content-type-options'), 'nosniff');
  assert.match(index.headers.get('x-robots-tag') || '', /noindex/);

  const spa = await get('/vault/some/deep/link');
  assert.equal(spa.status, 200);
  assert.equal(await spa.text(), html);

  const script = html.match(/src="(\/assets\/[^"]+\.js)"/)?.[1];
  assert.ok(script, 'index.html references a bundled script');
  const asset = await get(script);
  assert.equal(asset.status, 200);
  assert.match(asset.headers.get('content-type') || '', /javascript/);
  assert.equal((await get('/assets/does-not-exist.js')).status, 404);

  // Official clients embed this page in an iframe.
  const connector = await get('/webauthn-connector.html');
  assert.equal(connector.status, 200);
  assert.equal(connector.headers.get('x-frame-options'), null);
  assert.doesNotMatch(connector.headers.get('content-security-policy') || '', /frame-ancestors/);
  for (const page of ['/webauthn-fallback-connector.html', '/webauthn-mobile-connector.html']) {
    const response = await get(page);
    assert.equal(response.status, 200, page);
    assert.equal(response.headers.get('x-frame-options'), 'DENY', page);
  }
});

test('static-page headers never apply to API paths', async () => {
  const exists = async () => 'function' as const;
  for (const path of ['/api/sync', '/icons/example.com/icon.png', '/identity/connect/token', '/config', '/webauthn/x']) {
    const route = await resolveRoute(vercel.config, path, '', exists);
    assert.equal(route.kind, 'function', path);
    assert.equal(route.headers['Content-Security-Policy'], undefined, path);
    assert.equal(route.headers['X-Frame-Options'], undefined, path);
  }
});

test('API routes reach the function with path, query and CORS intact', async () => {
  for (const path of ['/api/config', '/api/config/', '/config', '/api/web-bootstrap', '/api/version']) {
    const response = await get(path);
    assert.equal(response.status, 200, `${path}: ${await response.clone().text()}`);
    assert.match(response.headers.get('content-type') || '', /json|text/, path);
  }
  const config = await (await get('/api/config')).json();
  assert.equal(config.environment.api, 'https://' + new URL(vercel.baseUrl).host + '/api');

  // Browser extension preflight.
  const preflight = await get('/api/sync', {
    method: 'OPTIONS',
    headers: {
      Origin: 'chrome-extension://nngceckbapebfimnlniiiahkandclblb',
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'authorization, bitwarden-client-name',
    },
  });
  assert.ok(preflight.status === 200 || preflight.status === 204, String(preflight.status));
  assert.equal(preflight.headers.get('access-control-allow-origin'), 'chrome-extension://nngceckbapebfimnlniiiahkandclblb');

  const unknown = await get('/api/definitely-not-a-route');
  assert.equal(unknown.status, 404);
  assert.match(unknown.headers.get('content-type') || '', /json/);
});

test('account, login and vault sync through the deployed function', async () => {
  alice = await client.registerAndLogin('alice@example.com');
  await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('smoke') });
  const full = await alice.json('/api/sync');
  assert.equal(full.ciphers.length, 1);
  assert.ok(full.domains, 'domains included by default');
  const lean = await alice.json('/api/sync?excludeDomains=true');
  assert.equal(lean.domains, null, 'query string reached the function');
  assert.equal(lean.profile.email, 'alice@example.com');
});

async function createAttachment(size: number): Promise<{ cipherId: string; response: Response; content: Buffer<ArrayBuffer> }> {
  const cipher = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload(`att-${size}`) });
  const content = Buffer.alloc(size, 7);
  const response = await alice.request(`/api/ciphers/${cipher.id}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('att-key'), fileName: fakeEncString('file'), fileSize: size },
  });
  return { cipherId: cipher.id, response, content };
}

test('attachments: inline download, presigned S3 redirect above 4 MB, oversize rejected up front', async () => {
  for (const size of [2048, 4_200_000]) {
    const { cipherId, response, content } = await createAttachment(size);
    assert.equal(response.status, 200, await response.clone().text());
    const meta = await response.json();
    const upload = await client.fetch(local(meta.url), {
      method: 'PUT',
      headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(size) },
      body: content,
    });
    assert.equal(upload.status, 201, await upload.text());

    const info = await alice.json(`/api/ciphers/${cipherId}/attachment/${meta.attachmentId}`);
    const download = await client.fetch(local(info.url));
    let body: Buffer;
    if (size > 4 * 1024 * 1024) {
      assert.equal(download.status, 302);
      const location = download.headers.get('location') || '';
      assert.ok(location.startsWith(process.env.S3_ENDPOINT || ''), location);
      body = Buffer.from(await (await fetch(location)).arrayBuffer());
    } else {
      assert.equal(download.status, 200);
      body = Buffer.from(await download.arrayBuffer());
    }
    assert.ok(body.equals(content), `attachment of ${size} bytes round-trips`);
  }

  // Too big for a Vercel request body: refused before metadata exists, so
  // the item never shows a broken attachment.
  const { cipherId, response } = await createAttachment(6 * 1024 * 1024);
  assert.equal(response.status, 400);
  assert.match((await response.json()).message, /too large/i);
  const cipher = await alice.json(`/api/ciphers/${cipherId}`);
  assert.equal((cipher.attachments || []).length, 0);

  // And the platform itself rejects bodies over its limit.
  const tooBig = await alice.request(`/api/ciphers/${cipherId}/attachment`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: new Uint8Array(VERCEL_BODY_LIMIT_BYTES + 1024),
  });
  assert.equal(tooBig.status, 413);
});

test('file send: upload, anonymous access and download', async () => {
  const content = Buffer.from('send-file-bytes-'.repeat(64));
  const created = await alice.json('/api/sends/file/v2', {
    method: 'POST',
    json: {
      type: 1,
      name: fakeEncString('file-send'),
      key: fakeEncString('send-key'),
      file: { fileName: fakeEncString('f.txt') },
      fileLength: content.length,
      deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
      disabled: false,
      hideEmail: false,
    },
  });
  const upload = await client.fetch(local(created.url), {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  });
  assert.equal(upload.status, 201, await upload.text());

  const send = created.sendResponse;
  const access = await client.fetch(`/api/sends/access/${send.accessId}`, { method: 'POST', json: {} });
  assert.equal(access.status, 200, await access.clone().text());
  const file = await client.fetch(`/api/sends/${send.id}/access/file/${send.file.id}`, { method: 'POST', json: {} });
  assert.equal(file.status, 200, await file.clone().text());
  const download = await client.fetch(local((await file.json()).url));
  assert.equal(download.status, 200);
  assert.ok(Buffer.from(await download.arrayBuffer()).equals(content));
});

test('Vercel Cron call is authenticated and its background work completes', async () => {
  const anonymous = await get('/api/internal/cron');
  assert.equal(anonymous.status, 401);
  const [cron] = await vercel.runCrons();
  assert.equal(cron.status, 200, await cron.text());
  await vercel.drainBackgroundWork();
});

test('realtime hub is absent so clients fall back to polling', async () => {
  const negotiate = await get('/notifications/hub/negotiate', {
    method: 'POST',
    headers: { Authorization: `Bearer ${alice.accessToken}` },
  });
  assert.equal(negotiate.status, 404);
});
