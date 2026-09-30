// The secrets the server keeps are sealed with ENCRYPTION_KEY: the database
// holds none of them in the clear, backups carry them so they restore onto a
// server with another key, and a wrong key is named instead of failing
// without explanation.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { unzipSync } from 'fflate';
import pg from 'pg';
import { createNodeHandler, type NodeHandler } from '../src/main/node';
import { Client, resetDatabase, TEST_DATABASE_URL, testServerEnv, type Session } from './helpers';
import { randomBase32Secret, TotpCodes } from './totp';

const KEY = 'secrets-test-encryption-key-0123456789abcdef';
const OTHER_KEY = 'another-encryption-key-another-0123456789abc';
const ADMIN = 'admin@example.com';
const BOB = 'bob@example.com';

let server: Server;
let app: NodeHandler;
let client: Client;
let admin: Session;
let bob: Session;
const codes = new TotpCodes();
const totpSecret = randomBase32Secret();
let recoveryCode: string;
let apiKey: string;

// Each deployment of the same database uses the given key.
async function deploy(encryptionKey: string): Promise<void> {
  await app?.dispose();
  app = createNodeHandler({ ...testServerEnv('mw-secrets'), ENCRYPTION_KEY: encryptionKey });
}

async function query<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
  const db = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await db.connect();
  try {
    return (await db.query(sql, params)).rows as T[];
  } finally {
    await db.end();
  }
}

const mph = (email: string) => Buffer.from('hash-' + email).toString('base64');

function token(fields: Record<string, string>): Promise<Response> {
  return client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ scope: 'api offline_access', client_id: 'cli', deviceType: '8', deviceName: 'e2e', deviceIdentifier: crypto.randomUUID(), ...fields }).toString(),
  });
}

async function totpLogin(): Promise<Response> {
  const { code } = await codes.next(totpSecret);
  return token({ grant_type: 'password', username: BOB, password: mph(BOB), twoFactorProvider: '0', twoFactorToken: code });
}

before(async () => {
  await resetDatabase();
  await deploy(KEY);
  server = createServer((req, res) => void app.handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  client = new Client(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  admin = await client.registerAndLogin(ADMIN);
  bob = await client.registerAndLogin(BOB);
});

after(async () => {
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await app?.dispose();
});

test('2FA seeds, recovery codes and API keys are stored sealed and still work', async () => {
  const { code } = await codes.next(totpSecret);
  const enabled = await bob.json('/api/accounts/totp', {
    method: 'PUT',
    json: { enabled: true, secret: totpSecret, token: code, masterPasswordHash: mph(BOB) },
  });
  recoveryCode = enabled.recoveryCode;
  apiKey = (await bob.json('/api/accounts/api-key', { method: 'POST', json: { masterPasswordHash: mph(BOB) } })).apiKey;

  const [user] = await query('SELECT api_key, recovery_code FROM users WHERE id = $1', [bob.userId]);
  const [provider] = await query('SELECT data FROM two_factor_providers WHERE user_id = $1 AND type = 0', [bob.userId]);
  for (const [stored, plain] of [
    [user.api_key, apiKey],
    [user.recovery_code, recoveryCode],
    [provider.data.secret, totpSecret],
  ]) {
    assert.match(stored, /^mw1\./);
    assert.ok(!stored.includes(plain));
  }

  assert.equal((await totpLogin()).status, 200);
  const byApiKey = await token({ grant_type: 'client_credentials', scope: 'api', client_id: `user.${bob.userId}`, client_secret: apiKey });
  assert.equal(byApiKey.status, 200, await byApiKey.clone().text());
});

test('a server with another ENCRYPTION_KEY names the problem', async () => {
  await deploy(OTHER_KEY);
  const response = await totpLogin();
  assert.equal(response.status, 500);
  assert.match((await response.json()).message, /ENCRYPTION_KEY/);
  await deploy(KEY);
});

test('backups carry the secrets in the clear, and a restore seals them with the new key', async () => {
  const exported = await admin.request('/api/admin/backup/export', {
    method: 'POST',
    json: { includeAttachments: false, masterPasswordHash: mph(ADMIN) },
  });
  assert.equal(exported.status, 200, await exported.clone().text());
  const bytes = new Uint8Array(await exported.arrayBuffer());
  const vault = JSON.parse(new TextDecoder().decode(unzipSync(bytes)['vault.json']));
  assert.equal(vault.users.find((user: any) => user.id === bob.userId).recoveryCode, recoveryCode);
  assert.equal(vault.twoFactorProviders.find((provider: any) => provider.userId === bob.userId).data.secret, totpSecret);
  assert.ok(!('apiKey' in vault.users[0]));

  // Restored on a deployment with another key.
  await deploy(OTHER_KEY);
  admin = await client.login(ADMIN);
  const form = new FormData();
  form.set('file', new Blob([bytes], { type: 'application/zip' }), /filename="([^"]+)"/.exec(exported.headers.get('Content-Disposition')!)![1]);
  form.set('masterPasswordHash', mph(ADMIN));
  form.set('replaceExisting', '1');
  const restored = await admin.request('/api/admin/backup/import', { method: 'POST', body: form });
  assert.equal(restored.status, 200, await restored.clone().text());

  const [provider] = await query('SELECT data FROM two_factor_providers WHERE user_id = $1 AND type = 0', [bob.userId]);
  assert.match(provider.data.secret, /^mw1\./);
  assert.equal((await totpLogin()).status, 200);
  const recover = await client.fetch('/identity/accounts/recover-2fa', {
    method: 'POST',
    json: { email: BOB, masterPasswordHash: mph(BOB), recoveryCode },
  });
  assert.equal(recover.status, 200, await recover.clone().text());
});
