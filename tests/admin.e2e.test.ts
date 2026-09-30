// What admins manage: accounts, invites and the audit log.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  blobExists,
  cipherPayload,
  Client,
  fakeEncString,
  fakeRsaEncString,
  startTestServer,
  TEST_DATABASE_URL,
  type Session,
  type TestServer,
} from './helpers';

let server: TestServer;
let client: Client;
let admin: Session;
let alice: Session;

const confirm = { masterPasswordHash: Buffer.from('hash-admin@example.com').toString('base64') };

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  admin = await client.registerAndLogin('admin@example.com');
  alice = await client.registerAndLogin('alice@example.com');
});

after(async () => {
  await server.close();
});

async function status(session: Session, path: string, init: RequestInit & { json?: unknown } = {}): Promise<number> {
  const response = await session.request(path, init);
  await response.arrayBuffer();
  return response.status;
}

async function organization(session: Session, name: string): Promise<{ orgId: string; collectionId: string }> {
  const org = await session.json('/api/organizations', {
    method: 'POST',
    json: {
      name,
      billingEmail: session.email,
      key: fakeRsaEncString('org-key'),
      collectionName: fakeEncString('Default'),
      keys: { publicKey: 'b3JnLXB1Yg==', encryptedPrivateKey: fakeEncString('org-private') },
      planType: 0,
    },
  });
  const sync = await session.json('/api/sync');
  return { orgId: org.id, collectionId: sync.collections.find((c: any) => c.organizationId === org.id).id };
}

// Uploads a file to the cipher and returns its key in the bucket.
async function attach(session: Session, cipherId: string): Promise<string> {
  const content = Buffer.from('attachment-bytes');
  const meta = await session.json(`/api/ciphers/${cipherId}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('k'), fileName: fakeEncString('f'), fileSize: content.length },
  });
  const url = new URL(meta.url);
  const upload = await client.fetch(url.pathname + url.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob' },
    body: content,
  });
  assert.equal(upload.status, 201);
  return `${cipherId}/${meta.attachmentId}`;
}

async function organizationExists(id: string): Promise<boolean> {
  const db = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await db.connect();
  try {
    return (await db.query('SELECT 1 FROM organizations WHERE id = $1', [id])).rowCount === 1;
  } finally {
    await db.end();
  }
}

test('only admins reach the admin routes', async () => {
  for (const [method, path] of [
    ['GET', '/api/admin/users'],
    ['PUT', `/api/admin/users/${admin.userId}/status`],
    ['DELETE', `/api/admin/users/${admin.userId}`],
    ['GET', '/api/admin/invites'],
    ['POST', '/api/admin/invites'],
    ['DELETE', '/api/admin/invites'],
    ['GET', '/api/admin/logs'],
    ['DELETE', '/api/admin/logs'],
    ['PUT', '/api/admin/logs/settings'],
  ]) {
    const init = method === 'GET' ? { method } : { method, json: confirm };
    assert.equal(await status(alice, path, init), 403, `${method} ${path}`);
  }
  assert.equal((await client.fetch('/api/admin/users')).status, 401);
});

test('invites: created with the master password, listed, removed', async () => {
  assert.equal(await status(admin, '/api/admin/invites', { method: 'POST', json: {} }), 400);
  assert.equal(await status(admin, '/api/admin/invites', { method: 'POST', json: { masterPasswordHash: 'd3Jvbmc=' } }), 400);
  assert.equal(await status(admin, '/api/admin/invites', { method: 'POST', json: { ...confirm, expiresInHours: 0 } }), 400);

  const created = await admin.json('/api/admin/invites', { method: 'POST', json: confirm });
  assert.equal(created.object, 'invite');
  assert.equal(created.status, 'active');
  assert.equal(created.inviteLink, `${server.baseUrl}/?invite=${created.code}`);
  const hours = (Date.parse(created.expiresAt) - Date.parse(created.createdAt)) / 3_600_000;
  assert.equal(hours, 24 * 7);

  const other = await admin.json('/api/admin/invites', { method: 'POST', json: { ...confirm, expiresInHours: 1 } });
  // Alice's invite was used when she registered.
  const active = await admin.json('/api/admin/invites');
  assert.deepEqual(active.data.map((invite: any) => invite.code).sort(), [created.code, other.code].sort());
  const all = await admin.json('/api/admin/invites?includeInactive=true');
  assert.equal(all.data.filter((invite: any) => invite.status === 'used').length, 1);

  assert.equal(await status(admin, '/api/admin/invites/no-such-invite', { method: 'DELETE', json: confirm }), 404);
  assert.equal(await status(admin, `/api/admin/invites/${other.code}`, { method: 'DELETE', json: confirm }), 204);

  const invalid = await admin.json('/api/admin/invites?scope=invalid', { method: 'DELETE', json: confirm });
  assert.equal(invalid.deleted, 1);
  assert.equal((await admin.json('/api/admin/invites?includeInactive=true')).data.length, 1);
  const everything = await admin.json('/api/admin/invites', { method: 'DELETE', json: confirm });
  assert.equal(everything.deleted, 1);
  assert.equal((await admin.json('/api/admin/invites?includeInactive=true')).data.length, 0);
});

test('users are listed, banned and let back in', async () => {
  const users = await admin.json('/api/admin/users');
  assert.deepEqual(
    users.data.map((user: any) => [user.email, user.role, user.status, user.twoFactorEnabled]),
    [
      ['admin@example.com', 'admin', 'active', false],
      ['alice@example.com', 'user', 'active', false],
    ],
  );

  const path = `/api/admin/users/${alice.userId}/status`;
  assert.equal(await status(admin, path, { method: 'PUT', json: { ...confirm, status: 'gone' } }), 400);
  assert.equal(await status(admin, `/api/admin/users/${admin.userId}/status`, { method: 'PUT', json: { ...confirm, status: 'banned' } }), 400);
  assert.equal(await status(admin, `/api/admin/users/${crypto.randomUUID()}/status`, { method: 'PUT', json: { ...confirm, status: 'banned' } }), 404);

  const banned = await admin.json(path, { method: 'PUT', json: { ...confirm, status: 'banned' } });
  assert.equal(banned.status, 'banned');
  assert.equal((await alice.request('/api/sync')).status, 401);
  await assert.rejects(client.login('alice@example.com'));

  await admin.json(path, { method: 'POST', json: { ...confirm, status: 'active' } });
  alice = await client.login('alice@example.com');
  assert.equal((await alice.request('/api/sync')).status, 200);
});

test('deleting a user takes their vault, files and sole-member organizations', async () => {
  const bob = await client.registerAndLogin('bob@example.com');
  const personal = await bob.json('/api/ciphers', { method: 'POST', json: cipherPayload('mine') });
  const personalFile = await attach(bob, personal.id);
  const own = await organization(bob, 'Bob alone');
  const orgCipher = await bob.json('/api/ciphers/create', {
    method: 'POST',
    json: { cipher: cipherPayload('org', { organizationId: own.orgId }), collectionIds: [own.collectionId] },
  });
  const orgFile = await attach(bob, orgCipher.id);

  // As the only owner of an organization with other members, Bob stays.
  const shared = await organization(bob, 'Shared');
  await bob.json(`/api/organizations/${shared.orgId}/users/invite`, {
    method: 'POST',
    json: { emails: ['alice@example.com'], type: 2, collections: [], groups: [] },
  });
  const members = await bob.json(`/api/organizations/${shared.orgId}/users`);
  assert.equal(members.data.length, 2);
  const refused = await admin.request(`/api/admin/users/${bob.userId}`, { method: 'DELETE', json: confirm });
  assert.equal(refused.status, 409);
  assert.match((await refused.json()).message, /last owner of organization "Shared"/);

  await bob.json(`/api/organizations/${shared.orgId}/delete`, { method: 'POST', json: { masterPasswordHash: Buffer.from('hash-bob@example.com').toString('base64') } });
  assert.equal(await status(admin, `/api/admin/users/${admin.userId}`, { method: 'DELETE', json: confirm }), 400);
  assert.equal(await status(admin, `/api/admin/users/${bob.userId}`, { method: 'DELETE', json: {} }), 400);
  assert.equal(await status(admin, `/api/admin/users/${bob.userId}`, { method: 'DELETE', json: confirm }), 204);

  assert.equal(await blobExists(personalFile), false);
  assert.equal(await blobExists(orgFile), false);
  assert.equal(await organizationExists(own.orgId), false);
  await assert.rejects(client.login('bob@example.com'));
  assert.equal(await status(admin, `/api/admin/users/${bob.userId}`, { method: 'DELETE', json: confirm }), 404);
});

test('the audit log: filters, pages, retention and clearing', async () => {
  const security = await admin.json('/api/admin/logs?category=security&limit=200');
  assert.ok(security.data.every((entry: any) => entry.category === 'security'));
  const status = security.data.find((entry: any) => entry.action === 'admin.user.status');
  assert.equal(status.actorEmail, 'admin@example.com');
  assert.equal(status.targetUserEmail, 'alice@example.com');
  assert.equal(JSON.parse(status.metadata).status, 'active');

  const searched = await admin.json('/api/admin/logs?q=ADMIN.INVITE');
  assert.ok(searched.data.length > 0);
  assert.ok(searched.data.every((entry: any) => entry.action.startsWith('admin.invite.')));
  assert.equal((await admin.json('/api/admin/logs?q=100%25')).total, 0);

  const first = await admin.json('/api/admin/logs?limit=2');
  assert.equal(first.data.length, 2);
  assert.equal(first.hasMore, true);
  assert.equal(first.continuationToken, '2');
  const everything = await admin.json('/api/admin/logs?limit=200');
  assert.equal(first.total, everything.total);
  assert.equal(everything.data.length, everything.total);
  const second = await admin.json('/api/admin/logs?limit=2&offset=2');
  assert.deepEqual(
    [...first.data, ...second.data].map((entry: any) => entry.id),
    everything.data.slice(0, 4).map((entry: any) => entry.id),
  );
  assert.equal((await admin.request('/api/admin/logs?limit=500')).status, 400);
  assert.equal((await admin.request('/api/admin/logs?from=yesterday')).status, 400);

  assert.deepEqual(await admin.json('/api/admin/logs/settings'), { object: 'auditLogSettings', retentionDays: 90, maxEntries: null });
  const both = await admin.request('/api/admin/logs/settings', { method: 'PUT', json: { retentionDays: 30, maxEntries: 1000 } });
  assert.equal(both.status, 400);
  assert.equal((await admin.request('/api/admin/logs/settings', { method: 'PUT', json: { retentionDays: 12 } })).status, 400);
  const kept = await admin.json('/api/admin/logs/settings', { method: 'PUT', json: { retentionDays: null, maxEntries: 1000 } });
  assert.deepEqual(kept, { object: 'auditLogSettings', retentionDays: null, maxEntries: 1000 });
  assert.deepEqual(await admin.json('/api/admin/logs/settings'), kept);

  const cleared = await admin.json('/api/admin/logs', { method: 'DELETE' });
  assert.ok(cleared.deleted >= everything.total);
  const after = await admin.json('/api/admin/logs');
  assert.deepEqual(after.data.map((entry: any) => entry.action), ['admin.audit.clear']);
});
