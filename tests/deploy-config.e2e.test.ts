// What a half-configured deployment reports: each missing piece of
// configuration must produce an error that names what to set, not a bare 500.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createNodeHandler, type NodeHandler } from '../src/main/node';
import { Client, cipherPayload, fakeEncString, resetDatabase, TEST_DATABASE_URL, testServerEnv } from './helpers';

let server: Server;
let baseUrl: string;
let app: NodeHandler;

// Each test deploys a different configuration behind the same URL.
async function deploy(env: Record<string, string>): Promise<void> {
  await app?.dispose();
  app = createNodeHandler(env);
}

before(async () => {
  await resetDatabase();
  server = createServer((req, res) => void app.handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await app?.dispose();
});

async function errorMessage(response: Response): Promise<string> {
  const body = await response.json();
  return body.message ?? body.error_description ?? body.error;
}

test('missing DATABASE_URL is named in the error', async () => {
  await deploy({});
  const response = await fetch(`${baseUrl}/api/config`);
  assert.equal(response.status, 500);
  assert.match(await errorMessage(response), /DATABASE_URL/);
});

test('unreachable database points at DATABASE_URL without leaking details', async () => {
  await deploy({ DATABASE_URL: 'postgres://mw:secret-password@127.0.0.1:1/nothing' });
  const response = await fetch(`${baseUrl}/api/config`);
  assert.equal(response.status, 500);
  const message = await errorMessage(response);
  assert.match(message, /DATABASE_URL/);
  assert.doesNotMatch(message, /secret-password|ECONNREFUSED/);
});

const JWT_SECRET = 'deploy-config-test-secret-0123456789abcdef';
const ENCRYPTION_KEY = 'deploy-config-encryption-key-0123456789abcdef';

test('missing JWT_SECRET is reported to the web vault and on sign-up', async () => {
  await deploy({ DATABASE_URL: TEST_DATABASE_URL, ENCRYPTION_KEY });
  const boot = await (await fetch(`${baseUrl}/api/web-bootstrap`)).json();
  assert.deepEqual(boot.secretProblem, { name: 'JWT_SECRET', reason: 'missing' });
  const client = new Client(baseUrl);
  await assert.rejects(client.register('first@example.com'), /JWT_SECRET is not set/);
});

test('a short ENCRYPTION_KEY is reported to the web vault and on sign-up', async () => {
  await deploy({ DATABASE_URL: TEST_DATABASE_URL, JWT_SECRET, ENCRYPTION_KEY: 'short' });
  const boot = await (await fetch(`${baseUrl}/api/web-bootstrap`)).json();
  assert.deepEqual(boot.secretProblem, { name: 'ENCRYPTION_KEY', reason: 'too_short' });
  const client = new Client(baseUrl);
  await assert.rejects(client.register('first@example.com'), /ENCRYPTION_KEY is not set or too weak/);
});

test('missing S3 settings are named before any upload starts', async () => {
  await deploy({ DATABASE_URL: TEST_DATABASE_URL, JWT_SECRET, ENCRYPTION_KEY });
  const client = new Client(baseUrl);
  const alice = await client.registerAndLogin('alice@example.com');
  const cipher = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('no-s3') });

  const attachment = await alice.request(`/api/ciphers/${cipher.id}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('k'), fileName: fakeEncString('f'), fileSize: 10 },
  });
  assert.equal(attachment.status, 400);
  assert.match(await errorMessage(attachment), /S3_ENDPOINT/);
  assert.equal((await alice.json(`/api/ciphers/${cipher.id}`)).attachments?.length ?? 0, 0);

  const send = await alice.request('/api/sends/file/v2', {
    method: 'POST',
    json: {
      type: 1,
      name: fakeEncString('s'),
      key: fakeEncString('k'),
      file: { fileName: fakeEncString('f') },
      fileLength: 10,
      deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
    },
  });
  assert.equal(send.status, 400);
  assert.match(await errorMessage(send), /S3_ENDPOINT/);

  // Everything that does not need file storage keeps working.
  assert.equal((await alice.json('/api/sync')).ciphers.length, 1);
});

test('wrong S3 credentials surface the S3 error code, not "not configured"', async () => {
  await deploy({
    ...testServerEnv('mw-deploy-config'),
    JWT_SECRET,
    ENCRYPTION_KEY,
    S3_SECRET_ACCESS_KEY: 'definitely-wrong-secret',
  });
  const client = new Client(baseUrl);
  const alice = await client.login('alice@example.com');
  const cipher = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('bad-s3') });
  const meta = await alice.json(`/api/ciphers/${cipher.id}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('k'), fileName: fakeEncString('f'), fileSize: 4 },
  });
  const url = new URL(meta.url);
  const upload = await client.fetch(url.pathname + url.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': '4' },
    body: 'abcd',
  });
  assert.equal(upload.status, 500);
  const message = await errorMessage(upload);
  assert.match(message, /File storage error \(HTTP 403/);
  assert.doesNotMatch(message, /definitely-wrong-secret/);
});
