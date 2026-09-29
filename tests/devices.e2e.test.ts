// Devices: the list, names, device keys, remembered devices and signing
// devices out.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { Client, TEST_DATABASE_URL, fakeEncString, fakeRsaEncString, startTestServer, type TestServer } from './helpers';
import { masterPasswordHash, nextIp } from './e2e-support';

let server: TestServer;
let client: Client;

async function query<T = any>(sql: string, params: unknown[] = []): Promise<T[]> {
  const db = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await db.connect();
  try {
    return (await db.query(sql, params)).rows as T[];
  } finally {
    await db.end();
  }
}

function remember(userId: string, deviceIdentifier: string, expiresAt = Date.now() + 3_600_000) {
  return query(
    'INSERT INTO trusted_two_factor_device_tokens(token, user_id, device_identifier, expires_at, security_stamp) VALUES($1, $2, $3, $4, $5)',
    [crypto.randomUUID(), userId, deviceIdentifier, expiresAt, 'stamp'],
  );
}

function refresh(refreshToken: string) {
  return client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': nextIp() },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: 'cli' }).toString(),
  });
}

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  await client.registerAndLogin('admin@example.com');
});

after(async () => {
  await server?.close();
});

test('a device registers itself, gets a note, and stores trusted-device keys', async () => {
  const alice = await client.registerAndLogin('alice@example.com');
  const identifier = crypto.randomUUID();

  const registered = await alice.json('/api/devices', {
    method: 'POST',
    json: { Identifier: identifier, Name: 'Pixel', Type: 0, PushToken: 'fcm-token' },
  });
  assert.equal(registered.id, identifier);
  assert.equal(registered.type, 0);
  const [row] = await query('SELECT push_token, push_uuid FROM devices WHERE device_identifier = $1', [identifier]);
  assert.equal(row.push_token, 'fcm-token');
  assert.ok(row.push_uuid);

  assert.equal((await alice.request('/api/devices', { method: 'POST', json: { name: 'no id', type: 0 } })).status, 400);

  const renamed = await alice.json(`/api/devices/${identifier}/name`, { method: 'PUT', json: { name: '  Work phone ' } });
  assert.equal(renamed.name, 'Work phone');
  assert.equal(renamed.systemName, 'Pixel');
  assert.equal((await alice.request(`/devices/${crypto.randomUUID()}/name`, { method: 'PUT', json: { name: 'x' } })).status, 404);

  const keys = { encryptedUserKey: fakeRsaEncString('uk'), encryptedPublicKey: fakeEncString('pub'), encryptedPrivateKey: fakeEncString('priv') };
  const trusted = await alice.json(`/api/devices/identifier/${identifier}/keys`, { method: 'PUT', json: keys });
  assert.equal(trusted.isTrusted, true);
  assert.equal((await alice.request(`/api/devices/${identifier}/keys`, { method: 'PUT', json: { encryptedUserKey: 'plain' } })).status, 400);

  const retrieved = await alice.json(`/api/devices/${identifier}/retrieve-keys`, { method: 'POST' });
  assert.equal(retrieved.object, 'protectedDevice');
  assert.equal(retrieved.encryptedUserKey, keys.encryptedUserKey);

  // Only the user key changes; the other keys stay.
  const rotated = fakeRsaEncString('rotated');
  const trust = await alice.json('/api/devices/update-trust', {
    method: 'POST',
    json: { currentDevice: null, otherDevices: [{ deviceId: identifier, encryptedUserKey: rotated }] },
  });
  assert.deepEqual(trust, { success: true, updated: 1 });
  const afterRotation = await alice.json(`/api/devices/identifier/${identifier}`);
  assert.equal(afterRotation.encryptedUserKey, rotated);
  assert.equal(afterRotation.encryptedPublicKey, keys.encryptedPublicKey);

  const untrusted = await alice.json('/api/devices/untrust', { method: 'POST', json: { devices: [identifier] } });
  assert.equal(untrusted.removed, 1);
  assert.equal((await alice.json(`/api/devices/${identifier}`)).isTrusted, false);

  const other = await client.registerAndLogin('other@example.com');
  assert.equal((await other.request(`/api/devices/${identifier}`)).status, 404);
});

test('remembered devices are listed, made permanent and forgotten', async () => {
  const bob = await client.registerAndLogin('bob@example.com');
  const gone = crypto.randomUUID();
  await remember(bob.userId, bob.deviceIdentifier);
  await remember(bob.userId, gone);
  await remember(bob.userId, crypto.randomUUID(), Date.now() - 1000);

  const listed = (await bob.json('/api/devices/authorized')).data;
  assert.equal(listed.length, 2);
  const current = listed.find((d: any) => d.identifier === bob.deviceIdentifier);
  assert.equal(current.trusted, true);
  assert.equal(current.hasStoredDevice, true);
  const removed = listed.find((d: any) => d.identifier === gone);
  assert.equal(removed.hasStoredDevice, false);
  assert.equal(removed.trustedTokenCount, 1);

  const permanent = await bob.json(`/api/devices/authorized/${gone}/permanent`, { method: 'POST' });
  assert.equal(permanent.trustedUntil, '2099-12-31T23:59:59.000Z');
  assert.equal((await bob.request(`/api/devices/authorized/${crypto.randomUUID()}/permanent`, { method: 'POST' })).status, 409);

  assert.deepEqual(await bob.json(`/api/devices/authorized/${gone}`, { method: 'DELETE' }), { success: true, removed: 1 });
  assert.equal((await bob.json('/api/devices/authorized', { method: 'DELETE' })).removed, 2);
  assert.equal((await bob.json('/api/devices/authorized')).data[0].trusted, false);
});

test('removing a device ends its sessions', async () => {
  await client.registerAndLogin('carol@example.com');
  const phone = await client.login('carol@example.com');
  const laptop = await client.login('carol@example.com');

  assert.deepEqual(await laptop.json(`/api/devices/${phone.deviceIdentifier}`, { method: 'DELETE' }), { success: true });
  assert.equal((await refresh(phone.refreshToken)).status, 400);
  assert.equal((await phone.request('/api/accounts/profile')).status, 401);
  assert.equal((await refresh(laptop.refreshToken)).status, 200);
  assert.deepEqual(await laptop.json(`/api/devices/${phone.deviceIdentifier}/deactivate`, { method: 'POST' }), { success: false });
});

test('removing all devices needs the master password and signs out everywhere', async () => {
  const dave = await client.registerAndLogin('dave@example.com');
  const second = await client.login('dave@example.com');
  await remember(dave.userId, dave.deviceIdentifier);

  const wrong = await dave.request('/api/devices', { method: 'DELETE', json: { masterPasswordHash: masterPasswordHash('nope') } });
  assert.equal(wrong.status, 400);

  const result = await dave.json('/api/devices', { method: 'DELETE', json: { masterPasswordHash: masterPasswordHash('dave@example.com') } });
  assert.deepEqual(result, { success: true, removedTrusted: 1, removedSessions: 2, removedDevices: 2 });
  assert.equal((await dave.request('/api/devices')).status, 401);
  assert.equal((await second.request('/api/devices')).status, 401);
  assert.equal((await refresh(second.refreshToken)).status, 400);
});

test('knowndevice answers for base64url or plain emails, and false when unsure', async () => {
  const erin = await client.registerAndLogin('erin@example.com');
  const known = (email: string, identifier: string) =>
    client.fetch('/api/devices/knowndevice', {
      headers: { 'X-Request-Email': email, 'X-Device-Identifier': identifier, 'X-Forwarded-For': nextIp() },
    }).then((response) => response.json());

  assert.equal(await known(Buffer.from('Erin@example.com').toString('base64url'), erin.deviceIdentifier), true);
  assert.equal(await known('erin@example.com', erin.deviceIdentifier), true);
  assert.equal(await known('erin@example.com', crypto.randomUUID()), false);
  assert.equal(await known('nobody@example.com', erin.deviceIdentifier), false);
  assert.equal(await known('', ''), false);
});
