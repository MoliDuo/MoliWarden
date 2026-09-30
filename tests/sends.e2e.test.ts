// Send access rules, black-box over HTTP.
//
// Anonymous recipients reach a Send two ways:
//   v1: POST /api/sends/access/:accessId (password hash in the JSON body)
//   v2: grant_type=send_access at /identity/connect/token, then
//       POST /api/sends/access (and /api/sends/access/file/:fileId) with that bearer token.
// The accessId is the base64url encoding of the Send id's 16 UUID bytes.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';
import { errorText, nextIp } from './e2e-support';

let server: TestServer;
let client: Client;
let alice: Session;
let bob: Session;

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  alice = await client.registerAndLogin('alice@example.com');
  bob = await client.registerAndLogin('bob@example.com');
});

after(async () => {
  await server?.close();
});

function accessIdOf(sendId: string): string {
  return Buffer.from(sendId.replace(/-/g, ''), 'hex').toString('base64url');
}

// What official clients send as the Send password: a base64 32-byte key-stretched hash.
function sendPasswordHash(label: string): string {
  return Buffer.from(label.padEnd(32, '#').slice(0, 32)).toString('base64');
}

function inDays(days: number): string {
  return new Date(Date.now() + days * 86400000).toISOString();
}

function textSendPayload(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 0,
    name: fakeEncString('send-name'),
    notes: null,
    key: fakeEncString('send-key'),
    text: { text: fakeEncString('send-text'), hidden: false },
    deletionDate: inDays(7),
    expirationDate: null,
    maxAccessCount: null,
    disabled: false,
    hideEmail: false,
    password: null,
    ...extra,
  };
}

async function createTextSend(owner: Session, extra: Record<string, unknown> = {}): Promise<any> {
  return owner.json('/api/sends', { method: 'POST', json: textSendPayload(extra) });
}

async function accessV1(accessId: string, body: Record<string, unknown> = {}, ip = nextIp()): Promise<Response> {
  return client.fetch(`/api/sends/access/${accessId}`, {
    method: 'POST',
    headers: { 'X-Forwarded-For': ip },
    json: body,
  });
}

async function sendAccessToken(sendId: string, extra: Record<string, string> = {}, ip = nextIp()) {
  const response = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': ip },
    body: new URLSearchParams({ grant_type: 'send_access', client_id: 'send', scope: 'api.send.access', send_id: sendId, ...extra }).toString(),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function accessV2(token: string | null, ip = nextIp()): Promise<Response> {
  return client.fetch('/api/sends/access', {
    method: 'POST',
    headers: { 'X-Forwarded-For': ip },
    json: {},
    ...(token ? { token } : {}),
  });
}

async function accessCount(owner: Session, sendId: string): Promise<number> {
  return (await owner.json(`/api/sends/${sendId}`)).accessCount;
}

test('accessId is the base64url of the send id bytes; owner reads the send', async () => {
  const send = await createTextSend(alice);
  assert.match(send.id, /^[0-9a-f-]{36}$/);
  assert.equal(send.accessId, accessIdOf(send.id));
  assert.equal(send.object, 'send');
  assert.equal(send.type, 0);
  assert.equal(send.accessCount, 0);
  assert.equal(send.password, null);
  assert.equal(send.authType, 2, 'no auth');
  assert.equal(send.disabled, false);
  assert.ok(send.text && typeof send.text.text === 'string');
  assert.equal(send.file, null);

  const fetched = await alice.json(`/api/sends/${send.id}`);
  assert.equal(fetched.id, send.id);
  assert.equal(fetched.accessId, send.accessId);
  const list = await alice.json('/api/sends');
  assert.equal(list.object, 'list');
  assert.ok(list.data.some((s: any) => s.id === send.id));
});

test('v1 anonymous text access returns the send and increments the access count', async () => {
  const send = await createTextSend(alice);
  const response = await accessV1(send.accessId);
  assert.equal(response.status, 200, await response.clone().text());
  const body = await response.json();
  assert.equal(body.object, 'send-access');
  assert.equal(body.id, send.id);
  assert.equal(body.type, 0);
  assert.equal(body.name, send.name);
  assert.equal(body.text.text, send.text.text);
  assert.equal(body.file, null);
  assert.equal(body.creatorIdentifier, 'alice@example.com');
  assert.ok(body.deletionDate);
  // Owner-only fields are not leaked to recipients.
  assert.equal(body.key, undefined);
  assert.equal(body.password, undefined);
  assert.equal(body.accessCount, undefined);

  assert.equal(await accessCount(alice, send.id), 1);
  await accessV1(send.accessId);
  assert.equal(await accessCount(alice, send.id), 2);

  // An unknown or malformed accessId is 404.
  assert.equal((await accessV1(accessIdOf(crypto.randomUUID()))).status, 404);
  assert.equal((await accessV1('not-an-access-id')).status, 404);
});

test('v2: send_access grant then bearer access; only the access (not the grant) counts', async () => {
  const send = await createTextSend(alice);
  const grant = await sendAccessToken(send.accessId);
  assert.equal(grant.status, 200, JSON.stringify(grant.body));
  assert.ok(grant.body.access_token);
  assert.equal(grant.body.token_type, 'Bearer');
  assert.ok(grant.body.expires_in > 0);
  assert.equal(await accessCount(alice, send.id), 0);

  const response = await accessV2(grant.body.access_token);
  assert.equal(response.status, 200, await response.clone().text());
  const body = await response.json();
  assert.equal(body.object, 'send-access');
  assert.equal(body.id, send.id);
  assert.equal(body.text.text, send.text.text);
  assert.equal(body.creatorIdentifier, 'alice@example.com');
  assert.equal(await accessCount(alice, send.id), 1);
});

test('v2 grant errors carry send_access_error_type', async () => {
  const missing = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Forwarded-For': nextIp() },
    body: new URLSearchParams({ grant_type: 'send_access', client_id: 'send', scope: 'api.send.access' }).toString(),
  });
  assert.equal(missing.status, 400);
  const missingBody = await missing.json();
  assert.equal(missingBody.error, 'invalid_request');
  assert.equal(missingBody.send_access_error_type, 'send_id_required');

  const unknown = await sendAccessToken(accessIdOf(crypto.randomUUID()));
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body.error, 'invalid_grant');
  assert.equal(unknown.body.send_access_error_type, 'send_id_invalid');
});

test('v2 access rejects missing, forged and non-send tokens', async () => {
  assert.equal((await accessV2(null)).status, 401);
  assert.equal((await accessV2('not.a.jwt')).status, 401);
  // A regular user access token is not a send access token.
  assert.equal((await accessV2(alice.accessToken)).status, 401);

  const send = await createTextSend(alice);
  const grant = await sendAccessToken(send.accessId);
  const [header, payload, signature] = grant.body.access_token.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  const other = await createTextSend(alice);
  const forgedPayload = Buffer.from(JSON.stringify({ ...claims, sub: other.id })).toString('base64url');
  assert.equal((await accessV2(`${header}.${forgedPayload}.${signature}`)).status, 401);
  assert.equal(await accessCount(alice, other.id), 0);
});

test('password-protected send: v1 requires the right password hash', async () => {
  const hash = sendPasswordHash('correct horse');
  const send = await createTextSend(alice, { password: hash });
  assert.equal(send.authType, 1, 'password auth');
  assert.ok(send.password, 'owner sees that a password is set');

  const ip = nextIp();
  const missing = await accessV1(send.accessId, {}, ip);
  assert.equal(missing.status, 401);
  assert.ok(errorText(await missing.json()));

  const wrong = await accessV1(send.accessId, { password: sendPasswordHash('wrong') }, ip);
  assert.equal(wrong.status, 400);
  assert.ok(errorText(await wrong.json()));
  assert.equal(await accessCount(alice, send.id), 0);

  const right = await accessV1(send.accessId, { password: hash }, ip);
  assert.equal(right.status, 200, await right.clone().text());
  assert.equal((await right.json()).id, send.id);
  assert.equal(await accessCount(alice, send.id), 1);
});

test('password-protected send: v2 grant requires password_hash_b64', async () => {
  const hash = sendPasswordHash('battery staple');
  const send = await createTextSend(alice, { password: hash });

  const missing = await sendAccessToken(send.accessId);
  assert.equal(missing.status, 400);
  assert.equal(missing.body.error, 'invalid_request');
  assert.equal(missing.body.send_access_error_type, 'password_hash_b64_required');

  const wrong = await sendAccessToken(send.accessId, { password_hash_b64: sendPasswordHash('nope') });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.error, 'invalid_grant');
  assert.equal(wrong.body.send_access_error_type, 'password_hash_b64_invalid');

  const right = await sendAccessToken(send.accessId, { password_hash_b64: hash });
  assert.equal(right.status, 200, JSON.stringify(right.body));
  const access = await accessV2(right.body.access_token);
  assert.equal(access.status, 200);
  assert.equal(await accessCount(alice, send.id), 1);
});

test('repeated wrong send passwords lock the client out', async () => {
  const hash = sendPasswordHash('lockout');
  const send = await createTextSend(alice, { password: hash });
  const ip = nextIp();
  let locked: { status: number; body: any } | null = null;
  for (let attempt = 0; attempt < 12 && !locked; attempt += 1) {
    const result = await sendAccessToken(send.accessId, { password_hash_b64: sendPasswordHash(`wrong-${attempt}`) }, ip);
    if (result.status === 429) locked = result;
    else assert.equal(result.status, 400);
  }
  assert.ok(locked, 'locked out after repeated failures');
  assert.equal(locked.body.send_access_error_type, 'too_many_password_attempts');
  // Even the right password is refused from that client while locked.
  const right = await sendAccessToken(send.accessId, { password_hash_b64: hash }, ip);
  assert.equal(right.status, 429);
  // Another client is unaffected.
  const elsewhere = await sendAccessToken(send.accessId, { password_hash_b64: hash });
  assert.equal(elsewhere.status, 200);
});

test('remove-password makes the send open again', async () => {
  const hash = sendPasswordHash('removable');
  const send = await createTextSend(alice, { password: hash });
  assert.equal((await accessV1(send.accessId)).status, 401);

  const removed = await alice.json(`/api/sends/${send.id}/remove-password`, { method: 'PUT' });
  assert.equal(removed.id, send.id);
  assert.equal(removed.password, null);
  assert.equal(removed.authType, 2);

  assert.equal((await accessV1(send.accessId)).status, 200);
  assert.equal((await sendAccessToken(send.accessId)).status, 200);

  // Another user cannot remove someone else's password.
  const guarded = await createTextSend(alice, { password: hash });
  assert.equal((await bob.request(`/api/sends/${guarded.id}/remove-password`, { method: 'PUT' })).status, 404);
  assert.equal((await accessV1(guarded.accessId)).status, 401);
});

test('maxAccessCount: access is denied once the count is reached', async () => {
  const send = await createTextSend(alice, { maxAccessCount: 2 });
  assert.equal(send.maxAccessCount, 2);
  assert.equal((await accessV1(send.accessId)).status, 200);
  const grant = await sendAccessToken(send.accessId);
  assert.equal((await accessV2(grant.body.access_token)).status, 200);
  assert.equal(await accessCount(alice, send.id), 2);

  assert.equal((await accessV1(send.accessId)).status, 404);
  const denied = await sendAccessToken(send.accessId);
  assert.equal(denied.status, 400);
  assert.equal(denied.body.send_access_error_type, 'send_id_invalid');
  // A token obtained earlier does not get around the limit.
  assert.equal((await accessV2(grant.body.access_token)).status, 404);
  assert.equal(await accessCount(alice, send.id), 2);

  // Raising the limit re-opens it.
  await alice.json(`/api/sends/${send.id}`, { method: 'PUT', json: { ...textSendPayload(), name: send.name, maxAccessCount: 3 } });
  assert.equal((await accessV1(send.accessId)).status, 200);
});

test('disabled sends are not accessible until re-enabled', async () => {
  const send = await createTextSend(alice, { disabled: true });
  assert.equal(send.disabled, true);
  assert.equal((await accessV1(send.accessId)).status, 404);
  const grant = await sendAccessToken(send.accessId);
  assert.equal(grant.status, 400);
  assert.equal(grant.body.send_access_error_type, 'send_id_invalid');

  const enabled = await alice.json(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ disabled: false }) });
  assert.equal(enabled.disabled, false);
  assert.equal((await accessV1(send.accessId)).status, 200);

  // Disabling revokes access for tokens issued before.
  const token = (await sendAccessToken(send.accessId)).body.access_token;
  await alice.json(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ disabled: true }) });
  assert.equal((await accessV2(token)).status, 404);
  assert.equal((await accessV1(send.accessId)).status, 404);
});

test('expired sends are not accessible', async () => {
  // A send cannot be created expired, but can be edited to be.
  const pastCreate = await alice.request('/api/sends', { method: 'POST', json: textSendPayload({ expirationDate: inDays(-1) }) });
  assert.equal(pastCreate.status, 400);

  const send = await createTextSend(alice, { expirationDate: inDays(2) });
  assert.ok(send.expirationDate);
  assert.equal((await accessV1(send.accessId)).status, 200);
  const token = (await sendAccessToken(send.accessId)).body.access_token;

  const expired = await alice.json(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ expirationDate: inDays(-1) }) });
  assert.ok(new Date(expired.expirationDate).getTime() < Date.now());
  assert.equal((await accessV1(send.accessId)).status, 404);
  const grant = await sendAccessToken(send.accessId);
  assert.equal(grant.status, 400);
  assert.equal(grant.body.send_access_error_type, 'send_id_invalid');
  assert.equal((await accessV2(token)).status, 404);

  // Clearing the expiration re-opens it.
  await alice.json(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ expirationDate: null }) });
  assert.equal((await accessV1(send.accessId)).status, 200);
});

test('deletion date: in the future, at most 31 days out, and required', async () => {
  const tooFar = await alice.request('/api/sends', { method: 'POST', json: textSendPayload({ deletionDate: inDays(32) }) });
  assert.equal(tooFar.status, 400);
  assert.ok(errorText(await tooFar.json()));
  const missing = await alice.request('/api/sends', { method: 'POST', json: textSendPayload({ deletionDate: null }) });
  assert.equal(missing.status, 400);
  const garbage = await alice.request('/api/sends', { method: 'POST', json: textSendPayload({ deletionDate: 'soon' }) });
  assert.equal(garbage.status, 400);

  const send = await createTextSend(alice, { deletionDate: inDays(30) });
  const editTooFar = await alice.request(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ deletionDate: inDays(40) }) });
  assert.equal(editTooFar.status, 400);
  assert.equal(new Date((await alice.json(`/api/sends/${send.id}`)).deletionDate).getTime(), new Date(send.deletionDate).getTime());

  const pastCreate = await alice.request('/api/sends', { method: 'POST', json: textSendPayload({ deletionDate: inDays(-1) }) });
  assert.equal(pastCreate.status, 400);
  const pastEdit = await alice.request(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ deletionDate: inDays(-1) }) });
  assert.equal(pastEdit.status, 400);
});

test('hideEmail hides the creator from recipients', async () => {
  const hidden = await createTextSend(alice, { hideEmail: true });
  assert.equal(hidden.hideEmail, true);
  const v1 = await (await accessV1(hidden.accessId)).json();
  assert.equal(v1.creatorIdentifier, null);
  const token = (await sendAccessToken(hidden.accessId)).body.access_token;
  const v2 = await (await accessV2(token)).json();
  assert.equal(v2.creatorIdentifier, null);
  assert.ok(!JSON.stringify(v1).includes('alice@example.com'));
  assert.ok(!JSON.stringify(v2).includes('alice@example.com'));

  const shown = await createTextSend(alice, { hideEmail: false });
  assert.equal((await (await accessV1(shown.accessId)).json()).creatorIdentifier, 'alice@example.com');
});

test('owner edits and deletes a send', async () => {
  const send = await createTextSend(alice);
  const newName = fakeEncString('renamed');
  const newText = fakeEncString('new-text');
  const edited = await alice.json(`/api/sends/${send.id}`, {
    method: 'PUT',
    json: textSendPayload({ name: newName, text: { text: newText, hidden: true }, maxAccessCount: 5, hideEmail: true }),
  });
  assert.equal(edited.id, send.id);
  assert.equal(edited.name, newName);
  assert.equal(edited.text.text, newText);
  assert.equal(edited.text.hidden, true);
  assert.equal(edited.maxAccessCount, 5);
  assert.equal(edited.hideEmail, true);
  const fetched = await alice.json(`/api/sends/${send.id}`);
  assert.equal(fetched.name, newName);
  const accessed = await (await accessV1(send.accessId)).json();
  assert.equal(accessed.name, newName);
  assert.equal(accessed.text.text, newText);

  // A send cannot change type.
  const retype = await alice.request(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ type: 1 }) });
  assert.equal(retype.status, 400);

  const del = await alice.request(`/api/sends/${send.id}`, { method: 'DELETE' });
  assert.equal(del.status, 200);
  assert.equal((await alice.request(`/api/sends/${send.id}`)).status, 404);
  assert.ok(!(await alice.json('/api/sends')).data.some((s: any) => s.id === send.id));
  assert.equal((await accessV1(send.accessId)).status, 404);
  assert.equal((await sendAccessToken(send.accessId)).status, 400);
});

test("another user cannot read, edit or delete someone else's send", async () => {
  const send = await createTextSend(alice);
  assert.equal((await bob.request(`/api/sends/${send.id}`)).status, 404);
  assert.ok(!(await bob.json('/api/sends')).data.some((s: any) => s.id === send.id));
  const edit = await bob.request(`/api/sends/${send.id}`, { method: 'PUT', json: textSendPayload({ name: fakeEncString('pwned'), disabled: true }) });
  assert.equal(edit.status, 404);
  const del = await bob.request(`/api/sends/${send.id}`, { method: 'DELETE' });
  assert.equal(del.status, 404);
  const bulk = await bob.request('/api/sends/delete', { method: 'POST', json: { ids: [send.id] } });
  assert.ok(bulk.status === 200 || bulk.status === 404, `bulk delete status ${bulk.status}`);

  const intact = await alice.json(`/api/sends/${send.id}`);
  assert.equal(intact.name, send.name);
  assert.equal(intact.disabled, false);
  assert.equal((await accessV1(send.accessId)).status, 200);

  // Unauthenticated owner endpoints are 401.
  assert.equal((await client.fetch(`/api/sends/${send.id}`)).status, 401);
  assert.equal((await client.fetch('/api/sends')).status, 401);
});

test('file send: create, upload, access via v1 and v2, download once; tampered tokens fail', async () => {
  const content = Buffer.from('encrypted-send-file-bytes-'.repeat(64));
  const created = await alice.json('/api/sends/file/v2', {
    method: 'POST',
    json: {
      type: 1,
      name: fakeEncString('file-send'),
      notes: null,
      key: fakeEncString('file-send-key'),
      file: { fileName: fakeEncString('file.bin') },
      fileLength: content.length,
      deletionDate: inDays(3),
      expirationDate: null,
      maxAccessCount: null,
      disabled: false,
      hideEmail: false,
      password: null,
    },
  });
  assert.equal(created.object, 'send-fileUpload');
  assert.equal(created.fileUploadType, 1);
  const send = created.sendResponse;
  assert.equal(send.type, 1);
  assert.equal(send.text, null);
  const fileId: string = send.file.id;
  assert.ok(fileId);
  assert.equal(String(send.file.size), String(content.length));
  assert.ok(send.file.sizeName);
  assert.equal(send.accessId, accessIdOf(send.id));

  // Text-send endpoint rejects file sends at creation.
  const wrongEndpoint = await alice.request('/api/sends', { method: 'POST', json: { ...textSendPayload(), type: 1 } });
  assert.equal(wrongEndpoint.status, 400);

  // Upload through the returned (Azure-style) URL.
  const uploadUrl = new URL(created.url);
  assert.ok(uploadUrl.pathname.includes(send.id) && uploadUrl.pathname.includes(fileId));
  const badToken = new URL(uploadUrl);
  badToken.searchParams.set('token', 'x' + (uploadUrl.searchParams.get('token') ?? ''));
  const rejected = await client.fetch(badToken.pathname + badToken.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  });
  assert.equal(rejected.status, 401);
  const upload = await client.fetch(uploadUrl.pathname + uploadUrl.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  });
  assert.equal(upload.status, 201, await upload.clone().text());
  const again = await client.fetch(uploadUrl.pathname + uploadUrl.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  });
  assert.equal(again.status, 409, 'a send file cannot be overwritten');

  // v1 metadata access: file sends only count file downloads.
  const meta = await accessV1(send.accessId);
  assert.equal(meta.status, 200);
  const metaBody = await meta.json();
  assert.equal(metaBody.type, 1);
  assert.equal(metaBody.file.id, fileId);
  assert.equal(metaBody.text, null);
  assert.equal(await accessCount(alice, send.id), 0);

  // v1 file access.
  const v1File = await client.fetch(`/api/sends/${send.accessId}/access/file/${fileId}`, {
    method: 'POST',
    headers: { 'X-Forwarded-For': nextIp() },
    json: {},
  });
  assert.equal(v1File.status, 200, await v1File.clone().text());
  const v1Body = await v1File.json();
  assert.equal(v1Body.object, 'send-fileDownload');
  assert.equal(v1Body.id, fileId);
  assert.equal(await accessCount(alice, send.id), 1);

  const download = new URL(v1Body.url);
  const tamperedToken = new URL(download);
  const t = download.searchParams.get('t') ?? '';
  tamperedToken.searchParams.set('t', t.slice(0, -2) + (t.endsWith('AA') ? 'BB' : 'AA'));
  assert.equal((await client.fetch(tamperedToken.pathname + tamperedToken.search)).status, 401);
  assert.equal((await client.fetch(download.pathname)).status, 401, 'token required');
  // The token is bound to its file.
  const otherFile = `/api/sends/${send.id}/${crypto.randomUUID()}${download.search}`;
  assert.equal((await client.fetch(otherFile)).status, 401);

  const got = await client.fetch(download.pathname + download.search);
  assert.equal(got.status, 200);
  assert.deepEqual(Buffer.from(await got.arrayBuffer()), content);
  assert.match(got.headers.get('Content-Disposition') ?? '', /^attachment/);
  const replay = await client.fetch(download.pathname + download.search);
  assert.equal(replay.status, 401, 'download tokens are single-use');

  // Wrong file id is 404.
  const wrongFile = await client.fetch(`/api/sends/${send.accessId}/access/file/${crypto.randomUUID()}`, {
    method: 'POST',
    headers: { 'X-Forwarded-For': nextIp() },
    json: {},
  });
  assert.equal(wrongFile.status, 404);

  // v2 file access.
  const grant = await sendAccessToken(send.accessId);
  assert.equal(grant.status, 200);
  const noToken = await client.fetch(`/api/sends/access/file/${fileId}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: {} });
  assert.equal(noToken.status, 401);
  const v2File = await client.fetch(`/api/sends/access/file/${fileId}`, {
    method: 'POST',
    headers: { 'X-Forwarded-For': nextIp() },
    token: grant.body.access_token,
    json: {},
  });
  assert.equal(v2File.status, 200, await v2File.clone().text());
  const v2Body = await v2File.json();
  assert.equal(v2Body.object, 'send-fileDownload');
  assert.equal(await accessCount(alice, send.id), 2);
  const v2Download = new URL(v2Body.url);
  const got2 = await client.fetch(v2Download.pathname + v2Download.search);
  assert.equal(got2.status, 200);
  assert.deepEqual(Buffer.from(await got2.arrayBuffer()), content);

  // Deleting the send removes access to the file.
  const pending = await client.fetch(`/api/sends/${send.accessId}/access/file/${fileId}`, {
    method: 'POST',
    headers: { 'X-Forwarded-For': nextIp() },
    json: {},
  });
  const pendingUrl = new URL((await pending.json()).url);
  assert.equal((await alice.request(`/api/sends/${send.id}`, { method: 'DELETE' })).status, 200);
  assert.equal((await client.fetch(pendingUrl.pathname + pendingUrl.search)).status, 404);
});

test('password-protected file send requires the password for file access', async () => {
  const content = Buffer.from('guarded-file');
  const hash = sendPasswordHash('file pw');
  const created = await alice.json('/api/sends/file/v2', {
    method: 'POST',
    json: {
      type: 1,
      name: fakeEncString('pw-file'),
      key: fakeEncString('k'),
      file: { fileName: fakeEncString('f') },
      fileLength: content.length,
      deletionDate: inDays(1),
      password: hash,
    },
  });
  const send = created.sendResponse;
  const url = new URL(created.url);
  assert.equal((await client.fetch(url.pathname + url.search, {
    method: 'PUT',
    headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
    body: content,
  })).status, 201);

  const path = `/api/sends/${send.accessId}/access/file/${send.file.id}`;
  const ip = nextIp();
  assert.equal((await client.fetch(path, { method: 'POST', headers: { 'X-Forwarded-For': ip }, json: {} })).status, 401);
  assert.equal((await client.fetch(path, { method: 'POST', headers: { 'X-Forwarded-For': ip }, json: { password: sendPasswordHash('bad') } })).status, 400);
  const ok = await client.fetch(path, { method: 'POST', headers: { 'X-Forwarded-For': ip }, json: { password: hash } });
  assert.equal(ok.status, 200);
  const download = new URL((await ok.json()).url);
  const got = await client.fetch(download.pathname + download.search);
  assert.deepEqual(Buffer.from(await got.arrayBuffer()), content);
});
