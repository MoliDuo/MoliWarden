// Security regressions: authorization boundaries the rewrite must keep, and
// holes found in review that stay closed.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { Client, TEST_DATABASE_URL, cipherPayload, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';
import { ROUTES } from './routes';

let server: TestServer;
let client: Client;
let admin: Session;
let alice: Session;

async function query<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
  const db = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await db.connect();
  try {
    return (await db.query(sql, params)).rows as T[];
  } finally {
    await db.end();
  }
}

function form(fields: Record<string, string>): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  };
}

function refresh(refreshToken: string): Promise<Response> {
  return client.fetch('/identity/connect/token', form({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: refreshToken }));
}

async function attachmentUrls(session: Session): Promise<{ cipherId: string; attachmentId: string; upload: URL; download: URL }> {
  const cipher = await session.json('/api/ciphers', { method: 'POST', json: cipherPayload('attachment') });
  const content = Buffer.from('encrypted-bytes');
  const meta = await session.json(`/api/ciphers/${cipher.id}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('att-key'), fileName: fakeEncString('file'), fileSize: content.length },
  });
  const upload = new URL(meta.url);
  const uploaded = await client.fetch(upload.pathname + upload.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  });
  assert.equal(uploaded.status, 201, await uploaded.clone().text());
  const info = await session.json(`/api/ciphers/${cipher.id}/attachment/${meta.attachmentId}`);
  return { cipherId: cipher.id, attachmentId: meta.attachmentId, upload, download: new URL(info.url) };
}

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  admin = await client.registerAndLogin('admin@example.com');
  alice = await client.registerAndLogin('alice@example.com');
});

after(async () => {
  await server?.close();
});

test('clear-token requires a bearer token and clears the push token', async () => {
  const path = `/api/devices/identifier/${alice.deviceIdentifier}/clear-token`;
  const anonymous = await client.fetch(path, { method: 'PUT' });
  assert.equal(anonymous.status, 401);

  const set = await alice.request(`/api/devices/identifier/${alice.deviceIdentifier}/token`, {
    method: 'PUT',
    json: { pushToken: 'push-token-value' },
  });
  assert.equal(set.status, 200, await set.clone().text());
  const [before] = await query('SELECT push_token FROM devices WHERE device_identifier = $1', [alice.deviceIdentifier]);
  assert.equal(before.push_token, 'push-token-value');

  const cleared = await alice.request(path, { method: 'PUT' });
  assert.equal(cleared.status, 200);
  const [afterClear] = await query('SELECT push_token FROM devices WHERE device_identifier = $1', [alice.deviceIdentifier]);
  assert.equal(afterClear.push_token, null);
});

test('non-admins are refused on every admin route', async () => {
  const bob = await client.registerAndLogin('bob@example.com');
  const problems: string[] = [];
  for (const [method, path, access] of ROUTES) {
    if (access !== 'admin' || path === '/api/internal/cron') continue;
    const sample = path.replace(/(?<=[/=]):([a-zA-Z]+)/g, (_, name: string) => (name === 'code' ? 'no-such-invite' : crypto.randomUUID()));
    const response = await bob.request(sample, {
      method,
      ...(method === 'GET' ? {} : { json: { masterPasswordHash: Buffer.from('hash-bob@example.com').toString('base64') } }),
    });
    if (response.status !== 403) problems.push(`${method} ${path} -> ${response.status}`);
  }
  assert.deepEqual(problems, []);
});

test('attachment and send tokens are not bearer tokens, and access tokens are not download tokens', async () => {
  const { cipherId, attachmentId, upload, download } = await attachmentUrls(alice);
  const uploadToken = upload.searchParams.get('token');
  const downloadToken = download.searchParams.get('token');
  assert.ok(uploadToken && downloadToken);

  const send = await alice.json('/api/sends', {
    method: 'POST',
    json: {
      type: 0,
      name: fakeEncString('send'),
      key: fakeEncString('send-key'),
      text: { text: fakeEncString('hello'), hidden: false },
      deletionDate: new Date(Date.now() + 86400000).toISOString(),
      disabled: false,
      hideEmail: false,
    },
  });
  const sendToken = await client.fetch('/identity/connect/token', form({ grant_type: 'send_access', client_id: 'send', scope: 'api.send.access', send_id: send.accessId }));
  assert.equal(sendToken.status, 200, await sendToken.clone().text());
  const sendAccessToken = (await sendToken.json()).access_token;

  for (const [label, token] of [['upload', uploadToken], ['download', downloadToken], ['send access', sendAccessToken]]) {
    const response = await client.fetch('/api/sync', { token });
    assert.equal(response.status, 401, `${label} token accepted as a bearer token`);
  }

  const withAccessToken = await client.fetch(`/api/attachments/${cipherId}/${attachmentId}?token=${encodeURIComponent(alice.accessToken)}`);
  assert.equal(withAccessToken.status, 401);
  // The genuine download token still works, so the refusal above is about the token.
  const genuine = await client.fetch(download.pathname + download.search);
  assert.equal(genuine.status, 200);
});

test('imported ciphers keep none of the server-owned fields a client sends', async () => {
  const foreignId = crypto.randomUUID();
  const response = await alice.request('/api/ciphers/import', {
    method: 'POST',
    json: {
      folders: [],
      folderRelationships: [],
      ciphers: [
        cipherPayload('imported', {
          id: foreignId,
          userId: admin.userId,
          organizationId: crypto.randomUUID(),
          collectionIds: [crypto.randomUUID()],
          edit: false,
          viewPassword: false,
          permissions: { delete: false, restore: false },
          organizationUseTotp: true,
          keyAddedFromRevision: '2020-01-01T00:00:00.000Z',
        }),
      ],
    },
  });
  assert.equal(response.status, 200, await response.clone().text());

  const rows = await query<{ id: string; data: string }>('SELECT id, data FROM ciphers WHERE user_id = $1', [alice.userId]);
  const imported = rows.map((row) => ({ id: row.id, data: typeof row.data === 'string' ? JSON.parse(row.data) : row.data }));
  assert.ok(imported.length >= 2);
  assert.ok(imported.every((row) => row.id !== foreignId), 'client-chosen id was used');
  const leaked = imported.flatMap((row) =>
    ['id', 'userId', 'organizationId', 'collectionIds', 'edit', 'viewPassword', 'permissions', 'organizationUseTotp', 'keyAddedFromRevision']
      .filter((key) => Object.prototype.hasOwnProperty.call(row.data, key)),
  );
  assert.deepEqual(leaked, []);

  const sync = await alice.json('/api/sync');
  const synced = sync.ciphers.filter((cipher: any) => cipher.organizationId !== null);
  assert.deepEqual(synced, []);
});

test('imports draw from a finite budget of their own; client headers change nothing', async () => {
  const carol = await client.registerAndLogin('carol@example.com');
  let status = 0;
  for (let i = 0; i < 250 && status !== 429; i++) {
    status = (await carol.request('/api/accounts/revision-date')).status;
  }
  assert.equal(status, 429);

  const emptyImport = { folders: [], folderRelationships: [], ciphers: [] };
  const importOnce = () =>
    carol.request('/api/ciphers/import', { method: 'POST', headers: { 'X-MoliWarden-Import': '1' }, json: emptyImport });
  assert.equal((await importOnce()).status, 200);
  for (let i = 0; i < 1100 && status !== 429; i++) status = (await importOnce()).status;
  assert.equal(status, 429);
});

test('a password change ends existing sessions', async () => {
  const dave = await client.registerAndLogin('dave@example.com');
  const changed = await dave.request('/api/accounts/password', {
    method: 'POST',
    json: {
      masterPasswordHash: Buffer.from('hash-dave@example.com').toString('base64'),
      newMasterPasswordHash: Buffer.from('new-hash-dave').toString('base64'),
      key: fakeEncString('new-user-key'),
    },
  });
  assert.equal(changed.status, 200, await changed.clone().text());

  assert.equal((await dave.request('/api/sync')).status, 401);
  assert.notEqual((await refresh(dave.refreshToken)).status, 200);
  await client.login('dave@example.com', 'new-hash-dave');
});

test('a banned user is locked out of existing sessions and new logins', async () => {
  const erin = await client.registerAndLogin('erin@example.com');
  const banned = await admin.request(`/api/admin/users/${erin.userId}/status`, {
    method: 'PUT',
    json: { status: 'banned', masterPasswordHash: Buffer.from('hash-admin@example.com').toString('base64') },
  });
  assert.equal(banned.status, 200, await banned.clone().text());

  assert.ok([401, 403].includes((await erin.request('/api/sync')).status));
  assert.notEqual((await refresh(erin.refreshToken)).status, 200);
  await assert.rejects(client.login('erin@example.com'));
});

test('password hints are refused unless the server enables them', async () => {
  const bootstrap = await (await client.fetch('/api/web-bootstrap')).json();
  assert.equal(bootstrap.passwordHintEnabled, false);
  const response = await client.fetch('/api/accounts/password-hint', {
    method: 'POST',
    headers: { Origin: server.baseUrl },
    json: { email: 'alice@example.com' },
  });
  assert.equal(response.status, 400);
  assert.doesNotMatch(await response.text(), /masterPasswordHint/);
});

test('password hints are returned when SHOW_PASSWORD_HINT=1', async () => {
  // A fresh server; this resets the database, so it runs last.
  await server.close();
  server = await startTestServer({ env: { SHOW_PASSWORD_HINT: '1' } });
  client = new Client(server.baseUrl);
  const registered = await client.fetch('/api/accounts/register', {
    method: 'POST',
    headers: { Origin: server.baseUrl },
    json: {
      email: 'hint@example.com',
      name: 'hint',
      masterPasswordHash: Buffer.from('hash-hint').toString('base64'),
      masterPasswordHint: 'the usual one',
      key: fakeEncString('user-key'),
      keys: { publicKey: Buffer.from('public-key').toString('base64'), encryptedPrivateKey: fakeEncString('private-key') },
      kdf: 0,
      kdfIterations: 600000,
    },
  });
  assert.equal(registered.status, 200, await registered.clone().text());

  const bootstrap = await (await client.fetch('/api/web-bootstrap')).json();
  assert.equal(bootstrap.passwordHintEnabled, true);
  const response = await client.fetch('/api/accounts/password-hint', {
    method: 'POST',
    headers: { Origin: server.baseUrl },
    json: { email: 'hint@example.com' },
  });
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await response.json()).masterPasswordHint, 'the usual one');
});
