// End-to-end tests for WebAuthn: account passkeys (login with passkey, PRF
// key sets) and WebAuthn as a second factor (provider 7). A software
// authenticator (tests/webauthn-soft.ts) stands in for the browser.
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, fakeEncString, startTestServer, type Session, type TestServer } from './helpers';
import { SoftAuthenticator, b64url, randomP256PrivateKey, type SoftCredential } from './webauthn-soft';

const EXTENSION_ORIGIN = 'chrome-extension://nngceckbapebfimnlniiiahkandclblb';
const CONFIGURED_ORIGIN = 'https://vault.example.test';
const RP_NAME = 'MoliWarden E2E';

let server: TestServer;
let client: Client;
let origin: string;

before(async () => {
  server = await startTestServer({
    env: { WEBAUTHN_RP_NAME: RP_NAME, WEBAUTHN_ALLOWED_ORIGINS: CONFIGURED_ORIGIN },
  });
  client = new Client(server.baseUrl);
  origin = server.baseUrl;
  // First user is the instance admin; it mints invites for everyone else.
  await client.registerAndLogin('admin@example.com');
});

after(async () => {
  await server?.close();
});

// --- helpers ----------------------------------------------------------------

function passwordHash(email: string): string {
  return Buffer.from('hash-' + email).toString('base64');
}

function errorText(body: any): string {
  return String(body?.message ?? body?.ErrorModel?.Message ?? body?.error_description ?? body?.error ?? '');
}

async function readBody(response: Response): Promise<any> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function call(session: Session, path: string, init: RequestInit & { json?: unknown } = {}): Promise<{ status: number; body: any }> {
  const response = await session.request(path, init);
  return { status: response.status, body: await readBody(response) };
}

// .NET Guid.ToByteArray() layout of a UUID, as used for WebAuthn user handles.
function dotNetGuidBytes(uuid: string): Buffer {
  const hex = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  return Buffer.from([hex[3], hex[2], hex[1], hex[0], hex[5], hex[4], hex[7], hex[6], ...hex.subarray(8)]);
}

async function tokenRequest(fields: Record<string, string>): Promise<{ status: number; body: any }> {
  const response = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  });
  return { status: response.status, body: await readBody(response) };
}

// Password grant with optional two-factor fields (Client.login has none).
async function passwordLogin(
  email: string,
  extra: Record<string, string> = {},
  deviceIdentifier: string = crypto.randomUUID(),
): Promise<{ status: number; body: any }> {
  return tokenRequest({
    grant_type: 'password',
    username: email,
    password: passwordHash(email),
    scope: 'api offline_access',
    client_id: 'cli',
    deviceType: '8',
    deviceIdentifier,
    deviceName: 'e2e',
    ...extra,
  });
}

async function passkeyLogin(token: string, deviceResponse: unknown): Promise<{ status: number; body: any }> {
  return tokenRequest({
    grant_type: 'webauthn',
    token,
    deviceResponse: typeof deviceResponse === 'string' ? deviceResponse : JSON.stringify(deviceResponse),
    scope: 'api offline_access',
    client_id: 'cli',
    deviceType: '8',
    deviceIdentifier: crypto.randomUUID(),
    deviceName: 'e2e-passkey',
  });
}

async function loginAssertionOptions(): Promise<{ options: any; token: string; body: any }> {
  const response = await client.fetch('/identity/accounts/webauthn/assertion-options');
  const body = await readBody(response);
  assert.equal(response.status, 200, JSON.stringify(body));
  return { options: body.options, token: body.token, body };
}

async function profileEmail(accessToken: string): Promise<string> {
  const response = await client.fetch('/api/accounts/profile', { token: accessToken });
  assert.equal(response.status, 200);
  return (await response.json()).email;
}

async function attestationOptions(session: Session): Promise<{ options: any; token: string; body: any }> {
  const { status, body } = await call(session, '/api/webauthn/attestation-options', {
    method: 'POST',
    json: { masterPasswordHash: passwordHash(session.email) },
  });
  assert.equal(status, 200, JSON.stringify(body));
  return { options: body.options, token: body.token, body };
}

function prfKeySet(label: string) {
  return {
    encryptedUserKey: `4.${Buffer.from(`prf-user-key-${label}`).toString('base64')}`,
    encryptedPublicKey: fakeEncString(`prf-public-${label}`),
    encryptedPrivateKey: fakeEncString(`prf-private-${label}`),
  };
}

// Registers a login passkey for `session` and returns the credential + server record.
async function registerAccountPasskey(
  session: Session,
  authenticator: SoftAuthenticator,
  body: Record<string, unknown> = {},
  style: 'w3c' | 'bitwarden' = 'w3c',
): Promise<{ credential: SoftCredential; record: any }> {
  const { options, token } = await attestationOptions(session);
  const { credential, response } = authenticator.create(options, { origin, style });
  const saved = await call(session, '/api/webauthn', {
    method: 'POST',
    json: { token, deviceResponse: response, name: 'Passkey', ...body },
  });
  assert.equal(saved.status, 200, JSON.stringify(saved.body));
  return { credential, record: saved.body };
}

async function listAccountPasskeys(session: Session): Promise<any[]> {
  const { status, body } = await call(session, '/api/webauthn');
  assert.equal(status, 200, JSON.stringify(body));
  return body.data;
}

// --- account passkeys ---------------------------------------------------------

describe('account passkeys (login with passkey)', () => {
  let alice: Session;
  let bob: Session;
  const authenticator = new SoftAuthenticator();
  let prfCredential: SoftCredential;
  let prfRecord: any;
  const prfKeys = prfKeySet('first');
  let plainCredential: SoftCredential;
  let plainRecord: any;

  before(async () => {
    alice = await client.registerAndLogin('alice@example.com');
    bob = await client.registerAndLogin('bob@example.com');
  });

  test('attestation options require authentication and the master password', async () => {
    const anonymous = await client.fetch('/api/webauthn/attestation-options', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(alice.email) },
    });
    assert.equal(anonymous.status, 401);

    const missing = await call(alice, '/api/webauthn/attestation-options', { method: 'POST', json: {} });
    assert.equal(missing.status, 400);
    const wrong = await call(alice, '/api/webauthn/attestation-options', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash('someone-else@example.com') },
    });
    assert.equal(wrong.status, 400);
  });

  test('attestation options describe a discoverable, user-verified ES256 credential with PRF', async () => {
    const { options, token, body } = await attestationOptions(alice);
    assert.equal(body.object, 'webauthnCredentialCreateOptions');
    assert.equal(typeof token, 'string');
    assert.ok(token.length > 0);
    assert.equal(typeof options.challenge, 'string');
    assert.match(options.challenge, /^[A-Za-z0-9_-]+$/);
    // RP id defaults to the request host; the name comes from WEBAUTHN_RP_NAME.
    assert.equal(options.rp.id, '127.0.0.1');
    assert.equal(options.rp.name, RP_NAME);
    // The user handle is the .NET GUID byte layout of the user id (official server compatible).
    assert.equal(options.user.id, b64url(dotNetGuidBytes(alice.userId)));
    assert.equal(options.user.name, alice.email);
    assert.ok(options.pubKeyCredParams.some((p: any) => p.type === 'public-key' && p.alg === -7));
    assert.equal(options.attestation, 'none');
    assert.equal(options.authenticatorSelection.residentKey, 'required');
    assert.equal(options.authenticatorSelection.requireResidentKey, true);
    assert.equal(options.authenticatorSelection.userVerification, 'required');
    assert.ok(options.extensions && 'prf' in options.extensions, 'PRF extension requested');
    assert.deepEqual(options.excludeCredentials ?? [], []);
  });

  test('registering a passkey with a PRF-encrypted key set', async () => {
    const { options, token } = await attestationOptions(alice);
    const { credential, response } = authenticator.create(options, { origin });
    assert.deepEqual(response.clientExtensionResults.prf, { enabled: true });
    const saved = await call(alice, '/api/webauthn', {
      method: 'POST',
      json: { token, deviceResponse: response, name: 'Laptop passkey', supportsPrf: true, ...prfKeys },
    });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal(saved.body.object, 'webauthnCredential');
    assert.equal(typeof saved.body.id, 'string');
    assert.equal(saved.body.name, 'Laptop passkey');
    assert.equal(saved.body.prfStatus, 0); // Enabled
    assert.equal(saved.body.encryptedUserKey, prfKeys.encryptedUserKey);
    assert.equal(saved.body.encryptedPublicKey, prfKeys.encryptedPublicKey);
    prfCredential = credential;
    prfRecord = saved.body;

    // The creation challenge is single use.
    const replay = await call(alice, '/api/webauthn', {
      method: 'POST',
      json: { token, deviceResponse: response, name: 'Again', supportsPrf: true, ...prfKeys },
    });
    assert.equal(replay.status, 400);

    const list = await listAccountPasskeys(alice);
    assert.equal(list.length, 1);
    assert.equal(list[0].id, prfRecord.id);
    assert.equal(list[0].name, 'Laptop passkey');
    assert.equal(list[0].prfStatus, 0);
    assert.equal(list[0].encryptedUserKey, prfKeys.encryptedUserKey);
    assert.equal(list[0].encryptedPublicKey, prfKeys.encryptedPublicKey);
    // Private key material is never listed.
    assert.equal(list[0].encryptedPrivateKey, undefined);
  });

  test('registering a second passkey (Bitwarden client shape) without a key set', async () => {
    const { options, token } = await attestationOptions(alice);
    // Already-registered credentials are excluded.
    assert.deepEqual((options.excludeCredentials ?? []).map((c: any) => c.id), [prfCredential.id]);
    assert.throws(() => authenticator.create(options, { origin }), /InvalidStateError/);

    const second = new SoftAuthenticator();
    const { credential, response } = second.create(options, { origin, style: 'bitwarden' });
    const saved = await call(alice, '/api/webauthn', {
      method: 'POST',
      json: { token, deviceResponse: response, name: 'Phone passkey', supportsPrf: true },
    });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal(saved.body.prfStatus, 1); // Supported, not yet enabled
    assert.equal(saved.body.encryptedUserKey, null);
    plainCredential = credential;
    plainRecord = saved.body;
    authenticator.credentials.push(credential);

    const list = await listAccountPasskeys(alice);
    assert.deepEqual(list.map((c) => c.id), [prfRecord.id, plainRecord.id]);
  });

  test('a passkey without PRF support reports prfStatus 2 and a default name', async () => {
    const { options, token } = await attestationOptions(bob);
    const { response } = new SoftAuthenticator().create(options, { origin });
    const saved = await call(bob, '/api/webauthn', { method: 'POST', json: { token, deviceResponse: response } });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal(saved.body.prfStatus, 2);
    assert.equal(typeof saved.body.name, 'string');
    assert.ok(saved.body.name.length > 0);
    // Other users' passkeys are not visible.
    assert.equal((await listAccountPasskeys(alice)).length, 2);
    assert.equal((await listAccountPasskeys(bob)).length, 1);
  });

  test('registration is rejected for a foreign origin, a wrong challenge, bad key sets and foreign tokens', async () => {
    const before = (await listAccountPasskeys(alice)).length;

    let opts = await attestationOptions(alice);
    let created = new SoftAuthenticator().create(opts.options, { origin: 'https://evil.example' });
    let res = await call(alice, '/api/webauthn', { method: 'POST', json: { token: opts.token, deviceResponse: created.response } });
    assert.equal(res.status, 400, 'foreign origin');

    opts = await attestationOptions(alice);
    created = new SoftAuthenticator().create(opts.options, { origin, clientData: { challenge: b64url(Buffer.alloc(32, 7)) } });
    res = await call(alice, '/api/webauthn', { method: 'POST', json: { token: opts.token, deviceResponse: created.response } });
    assert.equal(res.status, 400, 'wrong challenge');

    opts = await attestationOptions(alice);
    created = new SoftAuthenticator().create(opts.options, { origin, clientData: { type: 'webauthn.get' } });
    res = await call(alice, '/api/webauthn', { method: 'POST', json: { token: opts.token, deviceResponse: created.response } });
    assert.equal(res.status, 400, 'wrong clientData type');

    opts = await attestationOptions(alice);
    created = new SoftAuthenticator().create(opts.options, { origin, rpId: 'evil.example' });
    res = await call(alice, '/api/webauthn', { method: 'POST', json: { token: opts.token, deviceResponse: created.response } });
    assert.equal(res.status, 400, 'wrong RP id');

    opts = await attestationOptions(alice);
    created = new SoftAuthenticator().create(opts.options, { origin, userVerified: false });
    res = await call(alice, '/api/webauthn', { method: 'POST', json: { token: opts.token, deviceResponse: created.response } });
    assert.equal(res.status, 400, 'no user verification');

    opts = await attestationOptions(alice);
    created = new SoftAuthenticator().create(opts.options, { origin });
    res = await call(alice, '/api/webauthn', {
      method: 'POST',
      json: { token: opts.token, deviceResponse: created.response, encryptedUserKey: 'nope', encryptedPublicKey: 'nope', encryptedPrivateKey: 'nope' },
    });
    assert.equal(res.status, 400, 'invalid encrypted key set');

    // A creation token minted for alice cannot be redeemed by bob.
    opts = await attestationOptions(alice);
    created = new SoftAuthenticator().create(opts.options, { origin });
    res = await call(bob, '/api/webauthn', { method: 'POST', json: { token: opts.token, deviceResponse: created.response } });
    assert.equal(res.status, 400, 'token of another user');

    res = await call(alice, '/api/webauthn', { method: 'POST', json: { token: 'garbage', deviceResponse: created.response } });
    assert.equal(res.status, 400, 'garbage token');

    assert.equal((await listAccountPasskeys(alice)).length, before);
  });

  test('assertion options are public and ask for a discoverable, user-verified credential', async () => {
    const { options, token, body } = await loginAssertionOptions();
    assert.equal(body.object, 'webAuthnLoginAssertionOptions');
    assert.equal(typeof token, 'string');
    assert.equal(typeof options.challenge, 'string');
    assert.equal(options.rpId, '127.0.0.1');
    assert.equal(options.userVerification, 'required');
    assert.deepEqual(options.allowCredentials ?? [], []);
  });

  test('passkey login returns tokens and the PRF decryption option', async () => {
    const { options, token } = await loginAssertionOptions();
    const deviceResponse = authenticator.get(options, { origin, userHandle: true }, prfCredential);
    const { status, body } = await passkeyLogin(token, deviceResponse);
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(body.token_type, 'Bearer');
    assert.equal(typeof body.access_token, 'string');
    assert.equal(typeof body.refresh_token, 'string');
    assert.ok(body.expires_in > 0);
    assert.equal(typeof body.Key, 'string');
    assert.equal(typeof body.PrivateKey, 'string');
    assert.equal(typeof body.UserVerificationToken, 'string');
    const options2 = body.UserDecryptionOptions;
    assert.equal(options2.HasMasterPassword, true);
    assert.deepEqual(options2.WebAuthnPrfOption, {
      EncryptedPrivateKey: prfKeys.encryptedPrivateKey,
      EncryptedUserKey: prfKeys.encryptedUserKey,
      CredentialId: prfCredential.id,
      Transports: ['internal', 'hybrid'],
      Object: 'webAuthnPrfDecryptionOption',
    });
    assert.equal(await profileEmail(body.access_token), alice.email);

    const refreshed = await tokenRequest({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: body.refresh_token });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.body));
    assert.equal(typeof refreshed.body.access_token, 'string');
  });

  test('passkey login without PRF keys has no WebAuthnPrfOption; Bitwarden shape, base64 and no userHandle are accepted', async () => {
    const { options, token } = await loginAssertionOptions();
    const deviceResponse = authenticator.get(options, { origin, style: 'bitwarden', base64: true }, plainCredential);
    assert.equal(deviceResponse.response.userHandle, undefined);
    const { status, body } = await passkeyLogin(token, deviceResponse);
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(body.UserDecryptionOptions.WebAuthnPrfOption ?? null, null);
    assert.equal(await profileEmail(body.access_token), alice.email);
  });

  test('official browser extension and configured origins are accepted', async () => {
    for (const allowed of [EXTENSION_ORIGIN, CONFIGURED_ORIGIN]) {
      const { options, token } = await loginAssertionOptions();
      const deviceResponse = authenticator.get(options, { origin: allowed, userHandle: true }, prfCredential);
      const { status, body } = await passkeyLogin(token, deviceResponse);
      assert.equal(status, 200, `${allowed}: ${JSON.stringify(body)}`);
    }
  });

  test('a replayed assertion is rejected', async () => {
    const { options, token } = await loginAssertionOptions();
    const deviceResponse = authenticator.get(options, { origin, userHandle: true }, prfCredential);
    const first = await passkeyLogin(token, deviceResponse);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const replay = await passkeyLogin(token, deviceResponse);
    assert.equal(replay.status, 400);
    assert.equal(replay.body.error, 'invalid_grant');

    // Pairing the old assertion with a fresh challenge token does not help either.
    const fresh = await loginAssertionOptions();
    const mixed = await passkeyLogin(fresh.token, deviceResponse);
    assert.equal(mixed.status, 400);
    assert.equal(mixed.body.error, 'invalid_grant');
  });

  test('an assertion from an unknown credential or signed by the wrong key is rejected', async () => {
    const stranger = new SoftAuthenticator();
    const opts = await attestationOptions(bob); // just to mint a credential for the same RP
    const { credential: unknown } = stranger.create(opts.options, { origin });

    let { options, token } = await loginAssertionOptions();
    let result = await passkeyLogin(token, stranger.get(options, { origin, userHandle: true }, unknown));
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');

    ({ options, token } = await loginAssertionOptions());
    result = await passkeyLogin(token, authenticator.get(options, { origin, userHandle: true, signWith: randomP256PrivateKey() }, prfCredential));
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
  });

  test('assertions with a foreign origin, wrong RP id, no user verification or a forged user handle are rejected', async () => {
    const cases: Array<[string, Parameters<SoftAuthenticator['get']>[1]]> = [
      ['foreign origin', { origin: 'https://evil.example', userHandle: true }],
      ['wrong RP id', { origin, userHandle: true, rpId: 'evil.example' }],
      ['no user verification', { origin, userHandle: true, userVerified: false }],
      ['wrong clientData type', { origin, userHandle: true, clientData: { type: 'webauthn.create' } }],
    ];
    for (const [label, output] of cases) {
      const { options, token } = await loginAssertionOptions();
      const result = await passkeyLogin(token, authenticator.get(options, output, prfCredential));
      assert.equal(result.status, 400, label);
      assert.equal(result.body.error, 'invalid_grant', label);
    }

    // The user handle is not signed; a handle naming another user must not log in as them.
    const { options, token } = await loginAssertionOptions();
    const forged = authenticator.get(options, { origin, userHandle: true }, prfCredential);
    forged.response.userHandle = b64url(dotNetGuidBytes(bob.userId));
    const result = await passkeyLogin(token, forged);
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');
  });

  test('a signature counter that goes backwards is rejected', async () => {
    let { options, token } = await loginAssertionOptions();
    let result = await passkeyLogin(token, authenticator.get(options, { origin, userHandle: true, counter: 50 }, prfCredential));
    assert.equal(result.status, 200, JSON.stringify(result.body));

    ({ options, token } = await loginAssertionOptions());
    result = await passkeyLogin(token, authenticator.get(options, { origin, userHandle: true, counter: 10 }, prfCredential));
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');

    ({ options, token } = await loginAssertionOptions());
    result = await passkeyLogin(token, authenticator.get(options, { origin, userHandle: true, counter: 51 }, prfCredential));
    assert.equal(result.status, 200, JSON.stringify(result.body));
  });

  test('malformed webauthn grants are rejected with OAuth errors', async () => {
    const { options, token } = await loginAssertionOptions();
    const deviceResponse = authenticator.get(options, { origin, userHandle: true }, prfCredential);

    let result = await tokenRequest({ grant_type: 'webauthn', client_id: 'cli', deviceResponse: JSON.stringify(deviceResponse) });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_request');

    result = await tokenRequest({ grant_type: 'webauthn', client_id: 'cli', token });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_request');

    result = await passkeyLogin(token, '{not json');
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_request');

    // A token of another scope (credential creation) is not a login challenge.
    const creation = await attestationOptions(alice);
    result = await passkeyLogin(creation.token, authenticator.get({ ...options, challenge: creation.options.challenge }, { origin, userHandle: true }, prfCredential));
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'invalid_grant');

    // The original token was not burnt by the malformed attempts above.
    result = await passkeyLogin(token, deviceResponse);
    assert.equal(result.status, 200, JSON.stringify(result.body));
  });

  test('update-key-set assertion options require the master password and target one passkey', async () => {
    const anonymous = await client.fetch('/api/webauthn/assertion-options', { method: 'POST', json: {} });
    assert.equal(anonymous.status, 401);

    const wrong = await call(alice, '/api/webauthn/assertion-options', { method: 'POST', json: { masterPasswordHash: 'bad' } });
    assert.equal(wrong.status, 400);

    const unknown = await call(alice, '/api/webauthn/assertion-options', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(alice.email), credentialId: crypto.randomUUID() },
    });
    assert.equal(unknown.status, 404);

    const all = await call(alice, '/api/webauthn/assertion-options', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(alice.email) },
    });
    assert.equal(all.status, 200, JSON.stringify(all.body));
    assert.deepEqual(all.body.options.allowCredentials.map((c: any) => c.id).sort(), [prfCredential.id, plainCredential.id].sort());

    const one = await call(alice, '/api/webauthn/assertion-options', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(alice.email), credentialId: plainRecord.id },
    });
    assert.equal(one.status, 200, JSON.stringify(one.body));
    assert.equal(one.body.object, 'webAuthnLoginAssertionOptions');
    assert.equal(typeof one.body.token, 'string');
    assert.equal(one.body.options.userVerification, 'required');
    assert.deepEqual(one.body.options.allowCredentials.map((c: any) => c.id), [plainCredential.id]);
  });

  test('PUT /api/webauthn stores a PRF key set after a fresh assertion', async () => {
    const newKeys = prfKeySet('second');
    const opts = async () => {
      const { status, body } = await call(alice, '/api/webauthn/assertion-options', {
        method: 'POST',
        json: { masterPasswordHash: passwordHash(alice.email), credentialId: plainRecord.id },
      });
      assert.equal(status, 200, JSON.stringify(body));
      return body as { options: any; token: string };
    };

    // The key set is mandatory.
    let o = await opts();
    let result = await call(alice, '/api/webauthn', {
      method: 'PUT',
      json: { token: o.token, deviceResponse: authenticator.get(o.options, { origin }, plainCredential) },
    });
    assert.equal(result.status, 400);

    // A login-scope token is not accepted for key set updates.
    const login = await loginAssertionOptions();
    result = await call(alice, '/api/webauthn', {
      method: 'PUT',
      json: { token: login.token, deviceResponse: authenticator.get(login.options, { origin }, plainCredential), ...newKeys },
    });
    assert.equal(result.status, 400);

    // Bob cannot redeem alice's update token.
    o = await opts();
    result = await call(bob, '/api/webauthn', {
      method: 'PUT',
      json: { token: o.token, deviceResponse: authenticator.get(o.options, { origin }, plainCredential), ...newKeys },
    });
    assert.equal(result.status, 400);

    o = await opts();
    const deviceResponse = authenticator.get(o.options, { origin }, plainCredential);
    result = await call(alice, '/api/webauthn', { method: 'PUT', json: { token: o.token, deviceResponse, ...newKeys } });
    assert.equal(result.status, 200, JSON.stringify(result.body));

    // Single use.
    result = await call(alice, '/api/webauthn', { method: 'PUT', json: { token: o.token, deviceResponse, ...newKeys } });
    assert.equal(result.status, 400);

    const listed = (await listAccountPasskeys(alice)).find((c) => c.id === plainRecord.id);
    assert.equal(listed.prfStatus, 0);
    assert.equal(listed.encryptedUserKey, newKeys.encryptedUserKey);
    assert.equal(listed.encryptedPublicKey, newKeys.encryptedPublicKey);

    const loginOptions = await loginAssertionOptions();
    const loggedIn = await passkeyLogin(loginOptions.token, authenticator.get(loginOptions.options, { origin, userHandle: true }, plainCredential));
    assert.equal(loggedIn.status, 200, JSON.stringify(loggedIn.body));
    assert.equal(loggedIn.body.UserDecryptionOptions.WebAuthnPrfOption.EncryptedUserKey, newKeys.encryptedUserKey);
    assert.equal(loggedIn.body.UserDecryptionOptions.WebAuthnPrfOption.EncryptedPrivateKey, newKeys.encryptedPrivateKey);
    assert.equal(loggedIn.body.UserDecryptionOptions.WebAuthnPrfOption.CredentialId, plainCredential.id);
  });

  test('deleting a passkey requires the password and ownership, and disables login with it', async () => {
    let result = await call(alice, `/api/webauthn/${prfRecord.id}/delete`, { method: 'POST', json: { masterPasswordHash: 'bad' } });
    assert.equal(result.status, 400);

    result = await call(bob, `/api/webauthn/${prfRecord.id}/delete`, { method: 'POST', json: { masterPasswordHash: passwordHash(bob.email) } });
    assert.equal(result.status, 404, 'another user cannot delete it');

    result = await call(alice, `/api/webauthn/${crypto.randomUUID()}/delete`, { method: 'POST', json: { masterPasswordHash: passwordHash(alice.email) } });
    assert.equal(result.status, 404);

    result = await call(alice, `/api/webauthn/${prfRecord.id}/delete`, { method: 'POST', json: { masterPasswordHash: passwordHash(alice.email) } });
    assert.equal(result.status, 200, JSON.stringify(result.body));

    const list = await listAccountPasskeys(alice);
    assert.deepEqual(list.map((c) => c.id), [plainRecord.id]);

    const { options, token } = await loginAssertionOptions();
    const login = await passkeyLogin(token, authenticator.get(options, { origin, userHandle: true }, prfCredential));
    assert.equal(login.status, 400);
    assert.equal(login.body.error, 'invalid_grant');
  });

  test('at most five account passkeys can be registered', async () => {
    const carol = await client.registerAndLogin('carol@example.com');
    for (let i = 0; i < 5; i += 1) await registerAccountPasskey(carol, new SoftAuthenticator(), { name: `Key ${i + 1}` });
    assert.equal((await listAccountPasskeys(carol)).length, 5);
    const sixth = await call(carol, '/api/webauthn/attestation-options', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(carol.email) },
    });
    assert.equal(sixth.status, 400);
    assert.ok(errorText(sixth.body).length > 0);
  });
});

// --- WebAuthn as a second factor -------------------------------------------------

describe('WebAuthn two-step login (provider 7)', () => {
  const email = 'dave@example.com';
  let dave: Session;
  const authenticator = new SoftAuthenticator();
  let firstKey: SoftCredential;
  let secondKey: SoftCredential;

  async function relogin(): Promise<Session> {
    // Enabling/removing 2FA revokes refresh tokens; get a fresh session through 2FA if needed.
    const challenge = await passwordLogin(email);
    if (challenge.status === 200) {
      dave = await sessionFromToken(challenge.body);
      return dave;
    }
    const options = challenge.body.TwoFactorProviders2['7'];
    const key = authenticator.credentials.find((c) => options.allowCredentials.some((a: any) => a.id === c.id))!;
    const done = await passwordLogin(email, {
      twoFactorProvider: '7',
      twoFactorToken: JSON.stringify(authenticator.get(options, { origin, style: 'bitwarden' }, key)),
    });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    dave = await sessionFromToken(done.body);
    return dave;
  }

  async function sessionFromToken(token: any): Promise<Session> {
    const payload = JSON.parse(Buffer.from(token.access_token.split('.')[1], 'base64url').toString());
    const session: Session = {
      email,
      userId: payload.sub,
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      deviceIdentifier: '',
      request(path, init = {}) {
        return client.fetch(path, { ...init, token: session.accessToken });
      },
      async json(path, init = {}) {
        const res = await session.request(path, init);
        const text = await res.text();
        if (!res.ok) throw new Error(`${init.method || 'GET'} ${path} -> ${res.status}: ${text}`);
        return text ? JSON.parse(text) : null;
      },
    };
    return session;
  }

  async function registerTwoFactorKey(
    name: string,
    output: { style?: 'w3c' | 'bitwarden'; userVerified?: boolean } = {},
  ): Promise<{ credential: SoftCredential; body: any }> {
    const challenge = await call(dave, '/api/two-factor/get-webauthn-challenge', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(email) },
    });
    assert.equal(challenge.status, 200, JSON.stringify(challenge.body));
    // A separate security key (the first one would refuse: it is in excludeCredentials).
    const { credential, response } = new SoftAuthenticator().create(challenge.body, { origin, ...output });
    authenticator.credentials.push(credential);
    const saved = await call(dave, '/api/two-factor/webauthn', {
      method: 'PUT',
      json: { id: 1, name, masterPasswordHash: passwordHash(email), deviceResponse: response },
    });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    return { credential, body: saved.body };
  }

  before(async () => {
    dave = await client.registerAndLogin(email);
  });

  test('get-webauthn requires the master password and reports no keys initially', async () => {
    const wrong = await call(dave, '/api/two-factor/get-webauthn', { method: 'POST', json: { masterPasswordHash: 'bad' } });
    assert.equal(wrong.status, 400);

    const { status, body } = await call(dave, '/api/two-factor/get-webauthn', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(email) },
    });
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(body.Object ?? body.object, 'twoFactorWebAuthn');
    assert.equal(body.Enabled ?? body.enabled, false);
    assert.deepEqual(body.Keys ?? body.keys, []);
  });

  test('get-webauthn-challenge returns bare creation options for a security key', async () => {
    const wrong = await call(dave, '/api/two-factor/get-webauthn-challenge', { method: 'POST', json: { masterPasswordHash: 'bad' } });
    assert.equal(wrong.status, 400);

    const { status, body } = await call(dave, '/api/two-factor/get-webauthn-challenge', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(email) },
    });
    assert.equal(status, 200, JSON.stringify(body));
    assert.equal(typeof body.challenge, 'string');
    assert.equal(body.rp.id, '127.0.0.1');
    assert.equal(body.rp.name, RP_NAME);
    assert.equal(body.user.id, b64url(dotNetGuidBytes(dave.userId)));
    assert.equal(body.user.name, email);
    assert.equal(body.attestation, 'none');
    assert.equal(body.authenticatorSelection.userVerification, 'discouraged');
    assert.equal(body.authenticatorSelection.residentKey, 'discouraged');
    assert.ok(body.pubKeyCredParams.some((p: any) => p.alg === -7));
    assert.deepEqual(body.excludeCredentials ?? [], []);
  });

  test('PUT /api/two-factor/webauthn registers a key', async () => {
    const challenge = await call(dave, '/api/two-factor/get-webauthn-challenge', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(email) },
    });
    const { credential, response } = authenticator.create(challenge.body, { origin });

    const wrong = await call(dave, '/api/two-factor/webauthn', {
      method: 'PUT',
      json: { id: 1, name: 'YubiKey', masterPasswordHash: 'bad', deviceResponse: response },
    });
    assert.equal(wrong.status, 400);

    const saved = await call(dave, '/api/two-factor/webauthn', {
      method: 'PUT',
      json: { id: 1, name: 'YubiKey', masterPasswordHash: passwordHash(email), deviceResponse: response },
    });
    assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal(saved.body.Object ?? saved.body.object, 'twoFactorWebAuthn');
    assert.equal(saved.body.Enabled ?? saved.body.enabled, true);
    const keys = saved.body.Keys ?? saved.body.keys;
    assert.equal(keys.length, 1);
    assert.equal(keys[0].Id ?? keys[0].id, 1);
    assert.equal(keys[0].Name ?? keys[0].name, 'YubiKey');
    assert.equal(keys[0].Migrated ?? keys[0].migrated, false);
    firstKey = credential;

    // The registration challenge is single use.
    const replay = await call(dave, '/api/two-factor/webauthn', {
      method: 'PUT',
      json: { id: 2, name: 'Again', masterPasswordHash: passwordHash(email), deviceResponse: response },
    });
    assert.equal(replay.status, 400);

    // A foreign origin is rejected.
    const again = await call(dave, '/api/two-factor/get-webauthn-challenge', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(email) },
    });
    const foreign = new SoftAuthenticator().create(again.body, { origin: 'https://evil.example' });
    const rejected = await call(dave, '/api/two-factor/webauthn', {
      method: 'PUT',
      json: { id: 2, name: 'Evil', masterPasswordHash: passwordHash(email), deviceResponse: foreign.response },
    });
    assert.equal(rejected.status, 400);
  });

  test('the provider list shows WebAuthn as enabled', async () => {
    await relogin();
    const { status, body } = await call(dave, '/api/two-factor');
    assert.equal(status, 200, JSON.stringify(body));
    const data = body.Data ?? body.data;
    const webauthn = data.find((p: any) => (p.Type ?? p.type) === 7);
    assert.ok(webauthn, JSON.stringify(body));
    assert.equal(webauthn.Enabled ?? webauthn.enabled, true);

    const settings = await call(dave, '/api/two-factor/get-webauthn', { method: 'POST', json: { masterPasswordHash: passwordHash(email) } });
    assert.equal(settings.status, 200);
    assert.equal((settings.body.Keys ?? settings.body.keys).length, 1);
  });

  test('a password login without a second factor gets a WebAuthn challenge', async () => {
    const { status, body } = await passwordLogin(email);
    assert.equal(status, 400, JSON.stringify(body));
    assert.equal(body.error, 'invalid_grant');
    assert.equal(body.error_description, 'Two factor required.');
    assert.deepEqual(body.TwoFactorProviders, ['7']);
    const options = body.TwoFactorProviders2['7'];
    assert.equal(typeof options.challenge, 'string');
    assert.equal(options.rpId, '127.0.0.1');
    assert.equal(options.userVerification, 'discouraged');
    assert.deepEqual(options.allowCredentials.map((c: any) => [c.id, c.type]), [[firstKey.id, 'public-key']]);
    assert.ok('SsoEmail2faSessionToken' in body);
    assert.ok(body.MasterPasswordPolicy !== undefined);

    await assert.rejects(client.login(email), /Two factor required/);
  });

  test('signing the challenge completes the login (Bitwarden and W3C token shapes)', async () => {
    for (const style of ['bitwarden', 'w3c'] as const) {
      const challenge = await passwordLogin(email);
      const options = challenge.body.TwoFactorProviders2['7'];
      const deviceResponse = authenticator.get(options, { origin, style }, firstKey);
      const { status, body } = await passwordLogin(email, { twoFactorProvider: '7', twoFactorToken: JSON.stringify(deviceResponse) });
      assert.equal(status, 200, `${style}: ${JSON.stringify(body)}`);
      assert.equal(typeof body.access_token, 'string');
      assert.equal(typeof body.refresh_token, 'string');
      assert.equal(await profileEmail(body.access_token), email);
    }
  });

  test('user verification is not required for the second factor', async () => {
    const challenge = await passwordLogin(email);
    const options = challenge.body.TwoFactorProviders2['7'];
    const deviceResponse = authenticator.get(options, { origin, style: 'bitwarden', userVerified: false }, firstKey);
    const { status, body } = await passwordLogin(email, { twoFactorProvider: '7', twoFactorToken: JSON.stringify(deviceResponse) });
    assert.equal(status, 200, JSON.stringify(body));
  });

  test('twoFactorRemember returns a token that satisfies the next login on the same device', async () => {
    const deviceIdentifier = crypto.randomUUID();
    const challenge = await passwordLogin(email, {}, deviceIdentifier);
    const options = challenge.body.TwoFactorProviders2['7'];
    const deviceResponse = authenticator.get(options, { origin, style: 'bitwarden' }, firstKey);
    const first = await passwordLogin(
      email,
      { twoFactorProvider: '7', twoFactorToken: JSON.stringify(deviceResponse), twoFactorRemember: '1' },
      deviceIdentifier,
    );
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(typeof first.body.TwoFactorToken, 'string');

    const remembered = await passwordLogin(email, { twoFactorProvider: '5', twoFactorToken: first.body.TwoFactorToken }, deviceIdentifier);
    assert.equal(remembered.status, 200, JSON.stringify(remembered.body));

    // The remember token is bound to the device.
    const otherDevice = await passwordLogin(email, { twoFactorProvider: '5', twoFactorToken: first.body.TwoFactorToken });
    assert.equal(otherDevice.status, 400);
    assert.ok(otherDevice.body.TwoFactorProviders2?.['7'], 'falls back to the 2FA challenge');
  });

  test('replayed, forged, unknown and malformed second-factor assertions are rejected', async () => {
    const expectInvalid = (result: { status: number; body: any }, label: string) => {
      assert.equal(result.status, 400, `${label}: ${JSON.stringify(result.body)}`);
      assert.equal(result.body.error, 'invalid_grant', label);
      assert.equal(result.body.TwoFactorProviders2, undefined, `${label}: not a fresh challenge`);
    };

    // Replay.
    let challenge = await passwordLogin(email);
    let options = challenge.body.TwoFactorProviders2['7'];
    const good = JSON.stringify(authenticator.get(options, { origin, style: 'bitwarden' }, firstKey));
    const ok = await passwordLogin(email, { twoFactorProvider: '7', twoFactorToken: good });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    expectInvalid(await passwordLogin(email, { twoFactorProvider: '7', twoFactorToken: good }), 'replay');

    // Signed by the wrong key.
    challenge = await passwordLogin(email);
    options = challenge.body.TwoFactorProviders2['7'];
    expectInvalid(
      await passwordLogin(email, {
        twoFactorProvider: '7',
        twoFactorToken: JSON.stringify(authenticator.get(options, { origin, style: 'bitwarden', signWith: randomP256PrivateKey() }, firstKey)),
      }),
      'wrong key',
    );

    // Unknown credential.
    challenge = await passwordLogin(email);
    options = challenge.body.TwoFactorProviders2['7'];
    const stranger = new SoftAuthenticator();
    const { credential: unknown } = stranger.create(
      { challenge: options.challenge, rp: { id: options.rpId }, user: { id: b64url(Buffer.from('x')) } },
      { origin },
    );
    expectInvalid(
      await passwordLogin(email, { twoFactorProvider: '7', twoFactorToken: JSON.stringify(stranger.get(options, { origin }, unknown)) }),
      'unknown credential',
    );

    // Foreign origin.
    challenge = await passwordLogin(email);
    options = challenge.body.TwoFactorProviders2['7'];
    expectInvalid(
      await passwordLogin(email, {
        twoFactorProvider: '7',
        twoFactorToken: JSON.stringify(authenticator.get(options, { origin: 'https://evil.example' }, firstKey)),
      }),
      'foreign origin',
    );

    // A challenge the server never issued.
    expectInvalid(
      await passwordLogin(email, {
        twoFactorProvider: '7',
        twoFactorToken: JSON.stringify(authenticator.get({ ...options, challenge: b64url(Buffer.alloc(32, 9)) }, { origin }, firstKey)),
      }),
      'unissued challenge',
    );

    // Not JSON.
    expectInvalid(await passwordLogin(email, { twoFactorProvider: '7', twoFactorToken: 'not-json' }), 'garbage');

    // A correct login still works afterwards (failures below the lockout threshold).
    await relogin();
  });

  test('login passkeys and two-step keys are not interchangeable', async () => {
    // An account passkey (login purpose) cannot answer the 2FA challenge...
    await relogin();
    const loginAuth = new SoftAuthenticator();
    const { credential: loginPasskey } = await registerAccountPasskey(dave, loginAuth, { name: 'Dave passkey' });

    const challenge = await passwordLogin(email);
    const options = challenge.body.TwoFactorProviders2['7'];
    const asTwoFactor = await passwordLogin(email, {
      twoFactorProvider: '7',
      twoFactorToken: JSON.stringify(loginAuth.get(options, { origin }, loginPasskey)),
    });
    assert.equal(asTwoFactor.status, 400);
    assert.equal(asTwoFactor.body.error, 'invalid_grant');

    // ...and a two-step key cannot be used for passwordless login.
    const loginOptions = await loginAssertionOptions();
    const asPasskey = await passkeyLogin(loginOptions.token, authenticator.get(loginOptions.options, { origin, userHandle: true }, firstKey));
    assert.equal(asPasskey.status, 400);
    assert.equal(asPasskey.body.error, 'invalid_grant');

    // Two-step keys do not show up among account passkeys and vice versa.
    assert.deepEqual((await listAccountPasskeys(dave)).map((c) => c.name), ['Dave passkey']);

    // Passkey login bypasses the second factor (the passkey itself is multi-factor).
    const passkeyOptions = await loginAssertionOptions();
    const passwordless = await passkeyLogin(passkeyOptions.token, loginAuth.get(passkeyOptions.options, { origin, userHandle: true }, loginPasskey));
    assert.equal(passwordless.status, 200, JSON.stringify(passwordless.body));
  });

  test('a second key can be added, and the challenge then allows both', async () => {
    await relogin();
    const challenge = await call(dave, '/api/two-factor/get-webauthn-challenge', {
      method: 'POST',
      json: { masterPasswordHash: passwordHash(email) },
    });
    assert.deepEqual((challenge.body.excludeCredentials ?? []).map((c: any) => c.id), [firstKey.id]);

    // Security keys without user verification (no PIN) are fine for the second factor.
    const { credential, body } = await registerTwoFactorKey('Backup key', { style: 'bitwarden', userVerified: false });
    secondKey = credential;
    const keys = body.Keys ?? body.keys;
    assert.deepEqual(keys.map((k: any) => [k.Id ?? k.id, k.Name ?? k.name]), [[1, 'YubiKey'], [2, 'Backup key']]);

    const login = await passwordLogin(email);
    const allowed = login.body.TwoFactorProviders2['7'].allowCredentials.map((c: any) => c.id);
    assert.deepEqual(allowed.sort(), [firstKey.id, secondKey.id].sort());

    const done = await passwordLogin(email, {
      twoFactorProvider: '7',
      twoFactorToken: JSON.stringify(authenticator.get(login.body.TwoFactorProviders2['7'], { origin, style: 'bitwarden' }, secondKey)),
    });
    assert.equal(done.status, 200, JSON.stringify(done.body));
  });

  test('DELETE /api/two-factor/webauthn removes a key; its assertions stop working', async () => {
    await relogin();
    const wrong = await call(dave, '/api/two-factor/webauthn', { method: 'DELETE', json: { id: 1, masterPasswordHash: 'bad' } });
    assert.equal(wrong.status, 400);
    const missing = await call(dave, '/api/two-factor/webauthn', { method: 'DELETE', json: { id: 5, masterPasswordHash: passwordHash(email) } });
    assert.equal(missing.status, 400);

    const deleted = await call(dave, '/api/two-factor/webauthn', { method: 'DELETE', json: { id: 1, masterPasswordHash: passwordHash(email) } });
    assert.equal(deleted.status, 200, JSON.stringify(deleted.body));
    const keys = deleted.body.Keys ?? deleted.body.keys;
    assert.deepEqual(keys.map((k: any) => k.Name ?? k.name), ['Backup key']);
    assert.equal(deleted.body.Enabled ?? deleted.body.enabled, true);

    const login = await passwordLogin(email);
    const options = login.body.TwoFactorProviders2['7'];
    assert.deepEqual(options.allowCredentials.map((c: any) => c.id), [secondKey.id]);
    const removed = await passwordLogin(email, {
      twoFactorProvider: '7',
      twoFactorToken: JSON.stringify(authenticator.get(options, { origin, style: 'bitwarden' }, firstKey)),
    });
    assert.equal(removed.status, 400);
    assert.equal(removed.body.error, 'invalid_grant');
  });

  test('key ids are stable slots across deletions', { todo: 'ids are list positions (src/handlers/account-passkeys.ts:91 and :509), so deleting Key1 renumbers Key2 to 1; upstream Bitwarden keeps KeyN slots stable and a stale client could delete the wrong key' }, async () => {
    await relogin();
    const settings = await call(dave, '/api/two-factor/get-webauthn', { method: 'POST', json: { masterPasswordHash: passwordHash(email) } });
    const keys = settings.body.Keys ?? settings.body.keys;
    assert.deepEqual(keys.map((k: any) => [k.Id ?? k.id, k.Name ?? k.name]), [[2, 'Backup key']]);
  });

  test('the last key cannot be deleted individually; disabling the provider removes it', async () => {
    await relogin();
    const last = await call(dave, '/api/two-factor/webauthn', { method: 'DELETE', json: { id: 1, masterPasswordHash: passwordHash(email) } });
    assert.equal(last.status, 400);

    const wrong = await call(dave, '/api/two-factor/disable', { method: 'PUT', json: { type: 7, masterPasswordHash: 'bad' } });
    assert.equal(wrong.status, 400);
    const disabled = await call(dave, '/api/two-factor/disable', { method: 'PUT', json: { type: 7, masterPasswordHash: passwordHash(email) } });
    assert.equal(disabled.status, 200, JSON.stringify(disabled.body));
    assert.equal(disabled.body.Enabled ?? disabled.body.enabled, false);
    assert.equal(disabled.body.Type ?? disabled.body.type, 7);

    const login = await passwordLogin(email);
    assert.equal(login.status, 200, JSON.stringify(login.body));
    dave = await sessionFromToken(login.body);
    const settings = await call(dave, '/api/two-factor/get-webauthn', { method: 'POST', json: { masterPasswordHash: passwordHash(email) } });
    assert.equal(settings.body.Enabled ?? settings.body.enabled, false);
    assert.deepEqual(settings.body.Keys ?? settings.body.keys, []);
  });
});
