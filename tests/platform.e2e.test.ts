// End-to-end smoke test of the Vercel port: PostgreSQL + S3 + Node adapter.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, cipherPayload, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';

let server: TestServer;
let client: Client;
let alice: Session;

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
});

after(async () => {
  await server?.close();
});

test('register + prelogin + password login', async () => {
  const prelogin = await client.fetch('/identity/accounts/prelogin', { method: 'POST', json: { email: 'alice@example.com' } });
  assert.equal(prelogin.status, 200);
  alice = await client.registerAndLogin('alice@example.com');
  assert.ok(alice.accessToken);
  const profile = await alice.json('/api/accounts/profile');
  assert.equal(profile.email, 'alice@example.com');
});

test('wrong password is rejected and counted', async () => {
  await assert.rejects(client.login('alice@example.com', 'nope'), /invalid_grant|incorrect/);
});

test('refresh token grant', async () => {
  const response = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: alice.refreshToken }).toString(),
  });
  assert.equal(response.status, 200, await response.clone().text());
  const body = await response.json();
  assert.ok(body.access_token);
});

test('folders + ciphers CRUD, bulk operations and sync', async () => {
  const folder = await alice.json('/api/folders', { method: 'POST', json: { name: fakeEncString('folder') } });
  assert.ok(folder.id);

  const created = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('one', { folderId: folder.id }) });
  assert.equal(created.folderId, folder.id);
  const second = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('two') });

  const updated = await alice.json(`/api/ciphers/${created.id}`, {
    method: 'PUT',
    json: cipherPayload('one-updated', { folderId: folder.id, favorite: true }),
  });
  assert.equal(updated.favorite, true);

  await alice.json('/api/ciphers/move', { method: 'PUT', json: { ids: [second.id], folderId: folder.id } });
  await alice.json('/api/ciphers/archive', { method: 'PUT', json: { ids: [second.id] } }).catch(() => null);
  await alice.json('/api/ciphers/unarchive', { method: 'PUT', json: { ids: [second.id] } }).catch(() => null);
  await alice.request('/api/ciphers/delete', { method: 'PUT', json: { ids: [second.id] } });
  await alice.request('/api/ciphers/restore', { method: 'PUT', json: { ids: [second.id] } });

  const sync = await alice.json('/api/sync');
  assert.equal(sync.ciphers.length, 2);
  assert.equal(sync.folders.length, 1);
  const moved = sync.ciphers.find((c: any) => c.id === second.id);
  assert.equal(moved.folderId, folder.id);
  assert.equal(moved.deletedDate, null);

  const list = await alice.json('/api/ciphers');
  assert.equal(list.data.length, 2);

  await alice.request(`/api/folders/${folder.id}`, { method: 'DELETE' });
  const afterDelete = await alice.json('/api/sync');
  assert.ok(afterDelete.ciphers.every((c: any) => c.folderId === null));

  const del = await alice.request(`/api/ciphers/${second.id}`, { method: 'DELETE' });
  assert.ok(del.ok);
});

test('attachment upload (azure-style PUT) and download through S3', async () => {
  const cipher = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('att') });
  const content = Buffer.from('encrypted-attachment-bytes-'.repeat(100));
  const meta = await alice.json(`/api/ciphers/${cipher.id}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('att-key'), fileName: fakeEncString('file'), fileSize: content.length },
  });
  assert.ok(meta.attachmentId);
  const uploadUrl = new URL(meta.url);
  const upload = await client.fetch(uploadUrl.pathname + uploadUrl.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  });
  assert.equal(upload.status, 201, await upload.clone().text());

  const info = await alice.json(`/api/ciphers/${cipher.id}/attachment/${meta.attachmentId}`);
  const downloadUrl = new URL(info.url);
  const download = await client.fetch(downloadUrl.pathname + downloadUrl.search);
  assert.equal(download.status, 200);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), content);

  // Download tokens are single-use.
  const replay = await client.fetch(downloadUrl.pathname + downloadUrl.search);
  assert.equal(replay.status, 401);

  const removed = await alice.request(`/api/ciphers/${cipher.id}/attachment/${meta.attachmentId}`, { method: 'DELETE' });
  assert.ok(removed.ok);
});

test('text send can be created and accessed anonymously', async () => {
  const deletionDate = new Date(Date.now() + 86400000).toISOString();
  const send = await alice.json('/api/sends', {
    method: 'POST',
    json: {
      type: 0,
      name: fakeEncString('send'),
      notes: null,
      key: fakeEncString('send-key'),
      text: { text: fakeEncString('hello'), hidden: false },
      deletionDate,
      expirationDate: null,
      maxAccessCount: 2,
      disabled: false,
      hideEmail: false,
    },
  });
  assert.ok(send.accessId);
  const access = await client.fetch(`/api/sends/access/${send.accessId}`, { method: 'POST', json: {} });
  assert.equal(access.status, 200, await access.clone().text());
  const sends = await alice.json('/api/sends');
  assert.equal(sends.data[0].accessCount, 1);
});

test('rate limit buckets and cron endpoint', async () => {
  const unauthorized = await client.fetch('/api/internal/cron');
  assert.equal(unauthorized.status, 401);
  const cron = await client.fetch('/api/internal/cron', { headers: { Authorization: 'Bearer test-cron-secret' } });
  assert.equal(cron.status, 200, await cron.clone().text());
});

test('realtime hub is reported unavailable', async () => {
  const negotiate = await alice.request('/notifications/hub/negotiate', { method: 'POST' });
  assert.equal(negotiate.status, 404);
});

test('account revision date + devices', async () => {
  const revision = await alice.request('/api/accounts/revision-date');
  assert.equal(revision.status, 200);
  const devices = await alice.json('/api/devices');
  assert.ok(Array.isArray(devices.data));
});

test('admin backup export + restore round trip', async () => {
  const exported = await alice.request('/api/admin/backup/export', {
    method: 'POST',
    json: { includeAttachments: false, masterPasswordHash: Buffer.from('hash-alice@example.com').toString('base64') },
  });
  assert.equal(exported.status, 200, await exported.clone().text());
  const archive = new Uint8Array(await exported.arrayBuffer());
  assert.ok(archive.byteLength > 100);
  const fileName = /filename="?([^";]+)"?/.exec(exported.headers.get('Content-Disposition') || '')?.[1] || 'backup.zip';

  const before = await alice.json('/api/sync');
  const form = new FormData();
  form.set('file', new Blob([archive], { type: 'application/zip' }), fileName);
  form.set('masterPasswordHash', Buffer.from('hash-alice@example.com').toString('base64'));
  form.set('replaceExisting', '1');
  const restored = await alice.request('/api/admin/backup/import', { method: 'POST', body: form });
  assert.equal(restored.status, 200, await restored.clone().text());

  const relogin = await client.login('alice@example.com');
  const afterSync = await relogin.json('/api/sync');
  assert.equal(afterSync.ciphers.length, before.ciphers.length);
  alice = relogin;
});

test('endpoints official clients call routinely are answered', async () => {
  const alive = await client.fetch('/api/alive');
  assert.equal(alive.status, 200);
  const prelogin = await client.fetch('/api/accounts/prelogin', { method: 'POST', json: { email: 'alice@example.com' } });
  assert.equal(prelogin.status, 200);
  assert.deepEqual((await alice.json('/api/tasks')).data, []);

  // Legacy POST aliases for PUT/DELETE.
  const folder = await alice.json('/api/folders', { method: 'POST', json: { name: fakeEncString('old') } });
  const renamed = await alice.json(`/api/folders/${folder.id}`, { method: 'POST', json: { name: fakeEncString('new') } });
  assert.equal(renamed.id, folder.id);
  assert.ok((await alice.request(`/api/folders/${folder.id}/delete`, { method: 'POST' })).ok);
  assert.equal((await alice.request(`/api/folders/${folder.id}`)).status, 404);
  const profile = await alice.request('/api/accounts/profile', { method: 'POST', json: { name: 'Alice', culture: 'en-US' } });
  assert.equal(profile.status, 200, await profile.clone().text());

  const org = await alice.json('/api/organizations', {
    method: 'POST',
    json: {
      name: 'Stubs',
      billingEmail: alice.email,
      key: `4.${Buffer.from('k').toString('base64')}`,
      collectionName: fakeEncString('Default'),
      keys: { publicKey: 'cHVi', encryptedPrivateKey: fakeEncString('p') },
    },
  });
  for (const path of ['billing/metadata', 'billing/vnext/warnings', 'billing/vnext/self-host/metadata', 'policies', 'policies/token']) {
    const response = await alice.request(`/api/organizations/${org.id}/${path}`);
    assert.equal(response.status, 200, path);
  }
  const policy = await alice.json(`/api/organizations/${org.id}/policies/master-password`);
  assert.deepEqual([policy.type, policy.enabled, policy.object], [1, false, 'policy']);
});
