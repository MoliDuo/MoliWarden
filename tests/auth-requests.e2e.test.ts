// "Log in with device" (passwordless auth requests), black-box over HTTP.
//
// A new, logged-out device creates an auth request; the owner's logged-in
// device approves it with the user key encrypted to the request's public key;
// the new device then logs in with grant_type=password, password=<accessCode>
// and authRequest=<id>.
//
// Creating auth requests is rate limited per IP, per email and per device
// (5/min each), so every test uses its own users, devices and client IPs.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, fakeEncString, fakeRsaEncString, startTestServer, type Session, type TestServer } from './helpers';
import { errorText, nextIp } from './e2e-support';

let server: TestServer;
let client: Client;

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  // First user is the instance admin that mints invites for the others.
  await client.registerAndLogin('admin@example.com');
});

after(async () => {
  await server?.close();
});

interface NewDevice {
  deviceIdentifier: string;
  accessCode: string;
  publicKey: string;
  ip: string;
}

function newDevice(): NewDevice {
  return {
    deviceIdentifier: crypto.randomUUID(),
    accessCode: `code${crypto.randomUUID().replace(/-/g, '').slice(0, 21)}`,
    publicKey: Buffer.from(`device-public-key-${crypto.randomUUID()}`).toString('base64'),
    ip: nextIp(),
  };
}

async function createAuthRequest(
  email: string,
  device: NewDevice,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Promise<Response> {
  return client.fetch('/api/auth-requests', {
    method: 'POST',
    headers: { 'X-Forwarded-For': device.ip, 'Device-Type': '9', ...headers },
    json: {
      email,
      publicKey: device.publicKey,
      deviceIdentifier: device.deviceIdentifier,
      accessCode: device.accessCode,
      type: 0,
      fingerprintPhrase: 'alpha-bravo-charlie-delta-echo',
      ...extra,
    },
  });
}

async function createOk(email: string, device: NewDevice, extra: Record<string, unknown> = {}): Promise<any> {
  const response = await createAuthRequest(email, device, extra);
  const text = await response.text();
  assert.equal(response.status, 200, text);
  return JSON.parse(text);
}

async function poll(id: string, code: string, ip = nextIp()): Promise<Response> {
  return client.fetch(`/api/auth-requests/${id}/response?code=${encodeURIComponent(code)}`, {
    headers: { 'X-Forwarded-For': ip },
  });
}

async function approve(owner: Session, id: string, key: string | null, approved = true): Promise<Response> {
  return owner.request(`/api/auth-requests/${id}`, {
    method: 'PUT',
    json: {
      key,
      masterPasswordHash: null,
      deviceIdentifier: owner.deviceIdentifier,
      requestApproved: approved,
    },
  });
}

async function loginWithAuthRequest(email: string, device: NewDevice, authRequestId: string, accessCode = device.accessCode) {
  const form = new URLSearchParams({
    grant_type: 'password',
    username: email,
    password: accessCode,
    authRequest: authRequestId,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceIdentifier: device.deviceIdentifier,
    deviceName: 'new-device',
  });
  const response = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': device.ip },
    body: form.toString(),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

test('new device creates a request; owner lists, approves; new device polls and logs in with the approved key', async () => {
  const alice = await client.registerAndLogin('alice@example.com');
  const device = newDevice();

  const created = await createOk('Alice@Example.com', device);
  assert.match(created.id, /^[0-9a-f-]{36}$/);
  assert.equal(created.object, 'auth-request');
  assert.equal(created.publicKey, device.publicKey);
  assert.equal(created.requestDeviceIdentifier, device.deviceIdentifier);
  assert.equal(created.requestDeviceTypeValue, 9, 'device type comes from the Device-Type header');
  assert.equal(created.requestIpAddress, device.ip);
  assert.equal(created.key, null);
  assert.equal(created.masterPasswordHash, null);
  assert.equal(created.requestApproved, false);
  assert.equal(created.responseDate, null);
  assert.ok(created.creationDate);
  // The access code is a shared secret with the new device and is never echoed back.
  assert.ok(!JSON.stringify(created).includes(device.accessCode));

  // Owner sees it everywhere.
  const all = await alice.json('/api/auth-requests');
  assert.equal(all.object, 'list');
  assert.ok(all.data.some((r: any) => r.id === created.id));
  const pending = await alice.json('/api/auth-requests/pending');
  assert.equal(pending.object, 'list');
  const pendingRow = pending.data.find((r: any) => r.id === created.id);
  assert.ok(pendingRow, 'request is pending');
  assert.equal(pendingRow.requestDeviceId, device.deviceIdentifier);
  const single = await alice.json(`/api/auth-requests/${created.id}`);
  assert.equal(single.id, created.id);
  assert.equal(single.publicKey, device.publicKey);
  assert.equal(single.requestApproved, false);

  // New device polls: still pending.
  const pendingPoll = await poll(created.id, device.accessCode);
  assert.equal(pendingPoll.status, 200);
  const pendingBody = await pendingPoll.json();
  assert.equal(pendingBody.id, created.id);
  assert.equal(pendingBody.requestApproved, false);
  assert.equal(pendingBody.key, null);
  assert.equal(pendingBody.responseDate, null);

  // Owner approves with the user key encrypted to the device's public key.
  const approvedKey = fakeRsaEncString('user-key-for-device');
  const approval = await approve(alice, created.id, approvedKey);
  assert.equal(approval.status, 200, await approval.clone().text());
  const approvalBody = await approval.json();
  assert.equal(approvalBody.requestApproved, true);
  assert.equal(approvalBody.key, approvedKey);
  assert.ok(approvalBody.responseDate);

  // No longer pending.
  const pendingAfter = await alice.json('/api/auth-requests/pending');
  assert.ok(!pendingAfter.data.some((r: any) => r.id === created.id));

  // New device polls: approved, with the key.
  const approvedPoll = await poll(created.id, device.accessCode);
  assert.equal(approvedPoll.status, 200);
  const approvedBody = await approvedPoll.json();
  assert.equal(approvedBody.requestApproved, true);
  assert.equal(approvedBody.key, approvedKey);
  assert.ok(approvedBody.responseDate);
  assert.equal(approvedBody.masterPasswordHash, null);

  // A wrong access code does not log in (and does not burn the request).
  const wrong = await loginWithAuthRequest('alice@example.com', device, created.id, 'not-the-code');
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.error, 'invalid_grant');

  // Login with the access code as password.
  const login = await loginWithAuthRequest('alice@example.com', device, created.id);
  assert.equal(login.status, 200, JSON.stringify(login.body));
  assert.ok(login.body.access_token);
  assert.ok(login.body.refresh_token);
  assert.equal(login.body.Key, approvedKey, 'Key is the key from the approval, not the stored user key');
  const profile = await client.fetch('/api/accounts/profile', { token: login.body.access_token });
  assert.equal(profile.status, 200);
  assert.equal((await profile.json()).email, 'alice@example.com');

  // The new device is now a known device of the user.
  const devices = await alice.json('/api/devices');
  assert.ok(devices.data.some((d: any) => d.identifier === device.deviceIdentifier));

  // The same request cannot be used twice.
  const replay = await loginWithAuthRequest('alice@example.com', device, created.id);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');

  // It cannot be answered again either.
  const reanswer = await approve(alice, created.id, fakeRsaEncString('again'));
  assert.equal(reanswer.status, 409);
});

test('polling with a wrong or missing access code, or an unknown id, is 404', async () => {
  await client.registerAndLogin('poller@example.com');
  const device = newDevice();
  const created = await createOk('poller@example.com', device);

  assert.equal((await poll(created.id, 'wrong-code')).status, 404);
  assert.equal((await client.fetch(`/api/auth-requests/${created.id}/response`, { headers: { 'X-Forwarded-For': nextIp() } })).status, 404);
  assert.equal((await poll(crypto.randomUUID(), device.accessCode)).status, 404);
  assert.equal((await poll(created.id, device.accessCode)).status, 200);
});

test('a denied request reports the denial to the poller and cannot be used to log in', async () => {
  const carol = await client.registerAndLogin('carol@example.com');
  const device = newDevice();
  const created = await createOk('carol@example.com', device);

  const denial = await approve(carol, created.id, null, false);
  assert.equal(denial.status, 200, await denial.clone().text());
  const denialBody = await denial.json();
  assert.equal(denialBody.requestApproved, false);
  assert.ok(denialBody.responseDate);

  const polled = await (await poll(created.id, device.accessCode)).json();
  assert.equal(polled.requestApproved, false);
  assert.ok(polled.responseDate, 'the poller can tell the request was answered');
  assert.ok(!polled.key);

  const login = await loginWithAuthRequest('carol@example.com', device, created.id);
  assert.equal(login.status, 400);
  assert.equal(login.body.error, 'invalid_grant');
  assert.ok(!login.body.access_token);

  // A denial is final.
  const late = await approve(carol, created.id, fakeRsaEncString('late'));
  assert.equal(late.status, 409);
});

test('an unanswered request cannot be used to log in', async () => {
  await client.registerAndLogin('eager@example.com');
  const device = newDevice();
  const created = await createOk('eager@example.com', device);
  const login = await loginWithAuthRequest('eager@example.com', device, created.id);
  assert.equal(login.status, 400);
  assert.equal(login.body.error, 'invalid_grant');
});

test('approving requires a well-formed encrypted key', async () => {
  const frank = await client.registerAndLogin('frank@example.com');
  const device = newDevice();
  const created = await createOk('frank@example.com', device);

  const missing = await approve(frank, created.id, null, true);
  assert.equal(missing.status, 400);
  const garbage = await approve(frank, created.id, 'not-an-enc-string', true);
  assert.equal(garbage.status, 400);

  // Still pending and still approvable.
  const pending = await frank.json('/api/auth-requests/pending');
  assert.ok(pending.data.some((r: any) => r.id === created.id));
  const ok = await approve(frank, created.id, fakeEncString('sym-key'));
  assert.equal(ok.status, 200);
});

test('only the most recent request from a device is pending and approvable', async () => {
  const gina = await client.registerAndLogin('gina@example.com');
  const device = newDevice();
  const first = await createOk('gina@example.com', device);
  // Creation dates must differ for "latest" to be well defined.
  await new Promise((resolve) => setTimeout(resolve, 20));
  const second = await createOk('gina@example.com', { ...device, accessCode: 'second-code-0123456789', ip: nextIp() });

  const pending = await gina.json('/api/auth-requests/pending');
  const ids = pending.data.map((r: any) => r.id);
  assert.ok(ids.includes(second.id));
  assert.ok(!ids.includes(first.id), 'superseded request is not pending');
  // Both are still listed in the full history.
  const all = await gina.json('/api/auth-requests');
  const allIds = all.data.map((r: any) => r.id);
  assert.ok(allIds.includes(first.id) && allIds.includes(second.id));

  const stale = await approve(gina, first.id, fakeRsaEncString('stale'));
  assert.equal(stale.status, 400);
  const fresh = await approve(gina, second.id, fakeRsaEncString('fresh'));
  assert.equal(fresh.status, 200);
});

test('another user can neither read nor answer the request, nor log in with it', async () => {
  const henry = await client.registerAndLogin('henry@example.com');
  const mallory = await client.registerAndLogin('mallory@example.com');
  const device = newDevice();
  const created = await createOk('henry@example.com', device);

  assert.equal((await mallory.request(`/api/auth-requests/${created.id}`)).status, 404);
  const malloryList = await mallory.json('/api/auth-requests');
  assert.ok(!malloryList.data.some((r: any) => r.id === created.id));
  const malloryPending = await mallory.json('/api/auth-requests/pending');
  assert.ok(!malloryPending.data.some((r: any) => r.id === created.id));
  assert.equal((await approve(mallory, created.id, fakeRsaEncString('evil'))).status, 404);

  // Still untouched for its owner.
  const pending = await henry.json('/api/auth-requests/pending');
  assert.ok(pending.data.some((r: any) => r.id === created.id));
  const single = await henry.json(`/api/auth-requests/${created.id}`);
  assert.equal(single.requestApproved, false);
  assert.equal(single.responseDate, null);

  // After Henry approves, Mallory cannot use Henry's request for her own account.
  assert.equal((await approve(henry, created.id, fakeRsaEncString('henry-key'))).status, 200);
  const asMallory = await loginWithAuthRequest('mallory@example.com', device, created.id);
  assert.equal(asMallory.status, 400);
  assert.equal(asMallory.body.error, 'invalid_grant');
  // ...and the request is still usable by Henry.
  const asHenry = await loginWithAuthRequest('henry@example.com', device, created.id);
  assert.equal(asHenry.status, 200, JSON.stringify(asHenry.body));
});

test('an approved request can only be redeemed once, even under concurrent logins', async () => {
  const ivy = await client.registerAndLogin('ivy@example.com');
  const device = newDevice();
  const created = await createOk('ivy@example.com', device);
  assert.equal((await approve(ivy, created.id, fakeRsaEncString('ivy-key'))).status, 200);

  const results = await Promise.all(
    Array.from({ length: 6 }, () => loginWithAuthRequest('ivy@example.com', device, created.id)),
  );
  const successes = results.filter((r) => r.status === 200);
  assert.equal(successes.length, 1, `expected exactly one successful login, got ${successes.length}`);
});

test('unlock-type (1) requests can be created and approved but do not grant a login', async () => {
  const jack = await client.registerAndLogin('jack@example.com');
  const device = newDevice();
  const created = await createOk('jack@example.com', device, { type: 1 });
  const pending = await jack.json('/api/auth-requests/pending');
  assert.ok(pending.data.some((r: any) => r.id === created.id));
  assert.equal((await approve(jack, created.id, fakeRsaEncString('unlock'))).status, 200);
  const login = await loginWithAuthRequest('jack@example.com', device, created.id);
  assert.equal(login.status, 400);
  assert.equal(login.body.error, 'invalid_grant');
});

test('create validation: required fields, unknown user, admin-approval type on the public endpoint', async () => {
  await client.registerAndLogin('kate@example.com');
  const device = newDevice();

  for (const drop of ['email', 'publicKey', 'deviceIdentifier', 'accessCode']) {
    const response = await createAuthRequest('kate@example.com', device, { [drop]: undefined });
    assert.equal(response.status, 400, `missing ${drop}`);
    assert.ok(errorText(await response.json()));
  }
  const notJson = await client.fetch('/api/auth-requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp() },
    body: 'not json',
  });
  assert.equal(notJson.status, 400);

  const unknown = await createAuthRequest('nobody@example.com', newDevice());
  assert.equal(unknown.status, 400);

  const adminType = await createAuthRequest('kate@example.com', newDevice(), { type: 2 });
  assert.equal(adminType.status, 400);

  // The device identifier may also come from the X-Device-Identifier header.
  const headerDevice = newDevice();
  const viaHeader = await createAuthRequest(
    'kate@example.com',
    headerDevice,
    { deviceIdentifier: undefined },
    { 'X-Device-Identifier': headerDevice.deviceIdentifier },
  );
  assert.equal(viaHeader.status, 200, await viaHeader.clone().text());
  assert.equal((await viaHeader.json()).requestDeviceIdentifier, headerDevice.deviceIdentifier);
});

test('auth request creation is rate limited per email', async () => {
  await client.registerAndLogin('limited@example.com');
  const statuses: number[] = [];
  for (let i = 0; i < 6; i += 1) {
    statuses.push((await createAuthRequest('limited@example.com', newDevice())).status);
  }
  assert.deepEqual(statuses.slice(0, 5), [200, 200, 200, 200, 200]);
  assert.equal(statuses[5], 429);
});

test('authenticated admin-request records an admin-approval request that is not pending and cannot log in', async () => {
  const liam = await client.registerAndLogin('liam@example.com');
  const device = newDevice();

  const wrongType = await liam.request('/api/auth-requests/admin-request', {
    method: 'POST',
    json: { email: liam.email, publicKey: device.publicKey, deviceIdentifier: device.deviceIdentifier, accessCode: device.accessCode, type: 0 },
  });
  assert.equal(wrongType.status, 400);

  const otherEmail = await liam.request('/api/auth-requests/admin-request', {
    method: 'POST',
    json: { email: 'alice@example.com', publicKey: device.publicKey, deviceIdentifier: device.deviceIdentifier, accessCode: device.accessCode, type: 2 },
  });
  assert.equal(otherEmail.status, 400);

  const unauthenticated = await client.fetch('/api/auth-requests/admin-request', {
    method: 'POST',
    headers: { 'X-Forwarded-For': nextIp() },
    json: { email: liam.email, publicKey: device.publicKey, deviceIdentifier: device.deviceIdentifier, accessCode: device.accessCode, type: 2 },
  });
  assert.equal(unauthenticated.status, 401);

  const response = await liam.request('/api/auth-requests/admin-request', {
    method: 'POST',
    json: { email: liam.email, publicKey: device.publicKey, deviceIdentifier: device.deviceIdentifier, accessCode: device.accessCode, type: 2 },
  });
  assert.equal(response.status, 200, await response.clone().text());
  const created = await response.json();
  assert.equal(created.object, 'auth-request');
  assert.equal(created.requestApproved, false);

  const all = await liam.json('/api/auth-requests');
  assert.ok(all.data.some((r: any) => r.id === created.id));
  const pending = await liam.json('/api/auth-requests/pending');
  assert.ok(!pending.data.some((r: any) => r.id === created.id), 'admin-approval requests are not shown to the user for approval');
  assert.equal((await liam.json(`/api/auth-requests/${created.id}`)).id, created.id);
  assert.equal((await poll(created.id, device.accessCode)).status, 200);

  const login = await loginWithAuthRequest('liam@example.com', device, created.id);
  assert.equal(login.status, 400);
  assert.equal(login.body.error, 'invalid_grant');
});
