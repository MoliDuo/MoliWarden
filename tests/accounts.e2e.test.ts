// The account endpoints: registration, profile, master password, keys and
// the personal API key.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';

let server: TestServer;
let client: Client;
let admin: Session;
let alice: Session;

const b64 = (value: string) => Buffer.from(value).toString('base64');

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  admin = await client.registerAndLogin('admin@example.com');
  alice = await client.registerAndLogin('alice@example.com');
});

after(async () => {
  await server.close();
});

async function invite(): Promise<string> {
  const created = await admin.json('/api/admin/invites', {
    method: 'POST',
    json: { expiresInHours: 1, masterPasswordHash: b64('hash-admin@example.com') },
  });
  return created.code ?? created.invite?.code;
}

function register(email: string, inviteCode: string | undefined, headers: Record<string, string> = { Origin: server.baseUrl }) {
  return client.fetch('/api/accounts/register', {
    method: 'POST',
    headers: { ...headers, 'X-Forwarded-For': `10.98.0.${Math.floor(Math.random() * 250) + 1}` },
    json: {
      email,
      name: 'someone',
      masterPasswordHash: b64(`hash-${email}`),
      key: fakeEncString('user-key'),
      keys: { publicKey: b64('public-key'), encryptedPrivateKey: fakeEncString('private-key') },
      kdf: 0,
      kdfIterations: 600000,
      inviteCode,
    },
  });
}

async function message(response: Response): Promise<string> {
  return (await response.json()).message;
}

test('registration needs a valid invite before it tells whether an email is taken', async () => {
  const missing = await register('bob@example.com', undefined);
  assert.equal(missing.status, 403);
  assert.equal(await message(missing), 'Invite code is required');

  const bogus = await register('alice@example.com', 'not-an-invite');
  assert.equal(bogus.status, 403);
  assert.equal(await message(bogus), 'Invite code is invalid or expired');

  const code = await invite();
  const taken = await register('alice@example.com', code);
  assert.equal(taken.status, 409);
  assert.equal(await message(taken), 'Email already registered');

  // The failed attempt did not spend the invite.
  const ok = await register('bob@example.com', code);
  assert.equal(ok.status, 200, await ok.clone().text());
  assert.deepEqual(await ok.json(), { success: true, role: 'user' });
  assert.equal((await register('carol@example.com', code)).status, 403);
});

test('registration is refused from another site', async () => {
  const response = await register('mallory@example.com', await invite(), { Origin: 'https://evil.example' });
  assert.equal(response.status, 403);
});

test('registration checks the shape of the keys', async () => {
  const response = await client.fetch('/api/accounts/register', {
    method: 'POST',
    headers: { Origin: server.baseUrl },
    json: {
      email: 'dan@example.com',
      masterPasswordHash: b64('hash'),
      key: 'not-encrypted',
      keys: { publicKey: b64('public-key'), encryptedPrivateKey: fakeEncString('private-key') },
      inviteCode: await invite(),
    },
  });
  assert.equal(response.status, 400);
  assert.match(await message(response), /^key: /);
});

test('a profile update changes only the fields it names', async () => {
  const withHint = await alice.json('/api/accounts/profile', { method: 'PUT', json: { masterPasswordHint: '  the usual  ' } });
  assert.equal(withHint.masterPasswordHint, 'the usual');

  // Official clients send the name; leaving out the hint keeps it.
  const renamed = await alice.json('/api/accounts/profile', { method: 'PUT', json: { name: 'Alice A.', culture: 'en-US' } });
  assert.equal(renamed.name, 'Alice A.');
  assert.equal(renamed.masterPasswordHint, 'the usual');

  const cleared = await alice.json('/api/accounts/profile', { method: 'PUT', json: { masterPasswordHint: null } });
  assert.equal(cleared.masterPasswordHint, null);

  const tooLong = await alice.request('/api/accounts/profile', { method: 'PUT', json: { masterPasswordHint: 'x'.repeat(121) } });
  assert.equal(tooLong.status, 400);
});

test('keys change only with the master password, and a new user key clears its id', async () => {
  const setId = () => alice.request('/api/accounts/key-management/user-key-id', { method: 'POST', json: { userKeyId: 'key-1' } });
  assert.equal((await setId()).status, 200);
  assert.equal((await setId()).status, 422);

  const wrong = await alice.request('/api/accounts/keys', { method: 'POST', json: { masterPasswordHash: b64('nope'), key: fakeEncString('k') } });
  assert.equal(wrong.status, 400);
  assert.equal(await message(wrong), 'Invalid password');

  const key = fakeEncString('rotated-user-key');
  const keys = await alice.json('/api/accounts/keys', {
    method: 'POST',
    json: { masterPasswordHash: b64('hash-alice@example.com'), key },
  });
  assert.equal(keys.key, key);
  assert.equal((await alice.json('/api/accounts/keys')).key, key);
  assert.equal((await setId()).status, 200);
});

test('the API key is shown after the password check and replaced on rotation', async () => {
  const secret = { masterPasswordHash: b64('hash-alice@example.com') };
  const shown = await alice.json('/api/accounts/api-key', { method: 'POST', json: secret });
  assert.match(shown.apiKey, /^[A-Za-z0-9]{30}$/);
  assert.equal((await alice.json('/api/accounts/api-key', { method: 'POST', json: secret })).apiKey, shown.apiKey);

  const rotated = await alice.json('/api/accounts/rotate-api-key', { method: 'POST', json: secret });
  assert.notEqual(rotated.apiKey, shown.apiKey);
  assert.equal((await alice.request('/api/accounts/api-key', { method: 'POST', json: {} })).status, 400);
});

test('a password change with authentication and unlock data', async () => {
  const erin = await client.registerAndLogin('erin@example.com');
  const kdf = { kdfType: 0, iterations: 600000, memory: null, parallelism: null };
  const change = (salt: string, iterations = 600000) =>
    erin.request('/api/accounts/password', {
      method: 'POST',
      json: {
        masterPasswordHash: b64('hash-erin@example.com'),
        authenticationData: { kdf: { ...kdf, iterations }, masterPasswordAuthenticationHash: b64('new-erin'), salt },
        unlockData: { kdf: { ...kdf, iterations }, masterKeyWrappedUserKey: fakeEncString('rewrapped'), salt },
      },
    });

  assert.equal((await change('someone-else@example.com')).status, 400);
  assert.equal((await change('erin@example.com', 700000)).status, 400);
  const changed = await change('erin@example.com');
  assert.equal(changed.status, 200, await changed.clone().text());

  assert.equal((await erin.request('/api/accounts/profile')).status, 401);
  await assert.rejects(client.login('erin@example.com'));
  await client.login('erin@example.com', 'new-erin');
});

test('the revision date is a timestamp in milliseconds', async () => {
  const revision = await alice.json('/api/accounts/revision-date');
  assert.equal(typeof revision, 'number');
  assert.ok(Math.abs(Date.now() - revision) < 24 * 3600 * 1000);
});
