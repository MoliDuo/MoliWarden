// Two-step login (2FA): authenticator (TOTP), remember-me, recovery code and
// YubiKey OTP, driven the way official Bitwarden clients drive them.
//
// Black-box: talks to the server over HTTP only. The Yubico validation service
// is replaced by a local mock (tests/yubico-mock.ts).
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, startTestServer, type Session, type TestServer } from './helpers';
import { TotpCodes, randomBase32Secret, wrongTotp } from './totp';
import { startYubicoMock, yubiKeyOtp, yubiKeyPublicId, type YubicoMock } from './yubico-mock';

let server: TestServer;
let client: Client;
let yubico: YubicoMock;
let alice: Session; // instance admin (first user)

before(async () => {
  yubico = await startYubicoMock();
  server = await startTestServer({ env: { YUBICO_VALIDATION_URLS: yubico.url } });
  client = new Client(server.baseUrl);
  alice = await client.registerAndLogin('alice@example.com');
});

after(async () => {
  await server?.close();
  await yubico?.close();
});

// ---------------------------------------------------------------------------
// helpers

// The master password hash the harness registers users with.
function mph(email: string): string {
  return Buffer.from('hash-' + email).toString('base64');
}

// Read a response field regardless of PascalCase/camelCase (clients accept both).
function pick(obj: any, name: string): any {
  if (!obj || typeof obj !== 'object') return undefined;
  if (name in obj) return obj[name];
  const lower = name.toLowerCase();
  const key = Object.keys(obj).find((k) => k.toLowerCase() === lower);
  return key === undefined ? undefined : obj[key];
}

function errorText(body: any): string {
  return String(body?.message ?? body?.ErrorModel?.Message ?? body?.error_description ?? body?.error ?? '');
}

interface LoginOptions {
  password?: string;
  deviceIdentifier?: string;
  provider?: string | number;
  token?: string;
  remember?: boolean;
}

interface LoginResult {
  status: number;
  body: any;
  deviceIdentifier: string;
}

// Password grant as the official CLI sends it, plus the 2FA fields.
async function passwordLogin(email: string, options: LoginOptions = {}): Promise<LoginResult> {
  const deviceIdentifier = options.deviceIdentifier ?? crypto.randomUUID();
  const form = new URLSearchParams({
    grant_type: 'password',
    username: email,
    password: Buffer.from(options.password ?? 'hash-' + email).toString('base64'),
    scope: 'api offline_access',
    client_id: 'cli',
    deviceType: '8',
    deviceIdentifier,
    deviceName: 'e2e',
  });
  if (options.provider !== undefined) form.set('twoFactorProvider', String(options.provider));
  if (options.token !== undefined) form.set('twoFactorToken', options.token);
  if (options.remember) form.set('twoFactorRemember', '1');
  const response = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null, deviceIdentifier };
}

async function refreshGrant(refreshToken: string): Promise<{ status: number; body: any }> {
  const response = await client.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: 'cli', refresh_token: refreshToken }).toString(),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

function assertLoggedIn(result: LoginResult, label: string): void {
  assert.equal(result.status, 200, `${label}: ${JSON.stringify(result.body)}`);
  assert.equal(typeof result.body.access_token, 'string', label);
  assert.ok(result.body.access_token.length > 0, label);
}

// The challenge official clients parse to show the two-step login prompt.
function assertTwoFactorChallenge(result: LoginResult, providers: string[], label: string): void {
  assert.equal(result.status, 400, `${label}: ${JSON.stringify(result.body)}`);
  const body = result.body;
  assert.equal(body.error, 'invalid_grant', label);
  assert.equal(typeof body.error_description, 'string', label);
  assert.equal(body.access_token, undefined, label);
  assert.ok(Array.isArray(body.TwoFactorProviders), `${label}: TwoFactorProviders`);
  assert.deepEqual(body.TwoFactorProviders.map(String).sort(), [...providers].sort(), `${label}: TwoFactorProviders`);
  assert.ok(body.TwoFactorProviders2 && typeof body.TwoFactorProviders2 === 'object', `${label}: TwoFactorProviders2`);
  assert.deepEqual(Object.keys(body.TwoFactorProviders2).sort(), [...providers].sort(), `${label}: TwoFactorProviders2`);
  assert.ok(body.MasterPasswordPolicy && typeof body.MasterPasswordPolicy === 'object', `${label}: MasterPasswordPolicy`);
  assert.ok('SsoEmail2faSessionToken' in body, `${label}: SsoEmail2faSessionToken`);
}

// A failed two-step attempt: rejected, and not a token response.
function assertTwoFactorRejected(result: LoginResult, label: string): void {
  assert.equal(result.status, 400, `${label}: ${JSON.stringify(result.body)}`);
  assert.equal(result.body.error, 'invalid_grant', label);
  assert.equal(result.body.access_token, undefined, label);
}

async function api(token: string, path: string, init: RequestInit & { json?: unknown } = {}): Promise<{ status: number; body: any }> {
  const response = await client.fetch(path, { ...init, token });
  const text = await response.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: response.status, body };
}

async function enabledProviders(token: string): Promise<number[]> {
  const res = await api(token, '/api/two-factor');
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const data = pick(res.body, 'Data');
  assert.ok(Array.isArray(data));
  return data
    .filter((item: any) => pick(item, 'Enabled') === true)
    .map((item: any) => Number(pick(item, 'Type')))
    .sort();
}

// Web-vault flow: verify the master password, get a key, confirm with a code.
async function enableAuthenticator(session: Session, codes: TotpCodes): Promise<string> {
  const setup = await api(session.accessToken, '/api/two-factor/get-authenticator', {
    method: 'POST',
    json: { masterPasswordHash: mph(session.email) },
  });
  assert.equal(setup.status, 200, JSON.stringify(setup.body));
  const key = pick(setup.body, 'Key');
  const userVerificationToken = pick(setup.body, 'UserVerificationToken');
  const { code } = await codes.next(key);
  const enabled = await api(session.accessToken, '/api/two-factor/authenticator', {
    method: 'PUT',
    json: { key, token: code, userVerificationToken, masterPasswordHash: mph(session.email) },
  });
  assert.equal(enabled.status, 200, JSON.stringify(enabled.body));
  return key;
}

// ---------------------------------------------------------------------------
// Authenticator (TOTP, provider 0)

const BOB = 'bob@example.com';
let bob: Session;
let bobKey: string;
let bobUserVerificationToken: string;
let bobLatestAccessToken: string;
const bobCodes = new TotpCodes();

test('get-authenticator requires the master password and issues a base32 key', async () => {
  bob = await client.registerAndLogin(BOB);

  const missing = await api(bob.accessToken, '/api/two-factor/get-authenticator', { method: 'POST', json: {} });
  assert.equal(missing.status, 400);
  const wrong = await api(bob.accessToken, '/api/two-factor/get-authenticator', {
    method: 'POST',
    json: { masterPasswordHash: Buffer.from('not-the-password').toString('base64') },
  });
  assert.equal(wrong.status, 400);

  const setup = await api(bob.accessToken, '/api/two-factor/get-authenticator', {
    method: 'POST',
    json: { masterPasswordHash: mph(BOB) },
  });
  assert.equal(setup.status, 200, JSON.stringify(setup.body));
  bobKey = pick(setup.body, 'Key');
  bobUserVerificationToken = pick(setup.body, 'UserVerificationToken');
  assert.match(bobKey, /^[A-Z2-7]{16,}$/);
  assert.equal(pick(setup.body, 'Enabled'), false);
  assert.equal(typeof bobUserVerificationToken, 'string');
  assert.ok(bobUserVerificationToken.length > 0);

  assert.deepEqual(await enabledProviders(bob.accessToken), []);
  const status = await api(bob.accessToken, '/api/accounts/totp');
  assert.equal(status.status, 200);
  assert.equal(pick(status.body, 'enabled'), false);
});

test('enabling the authenticator needs a current code and the verification token', async () => {
  const wrongCode = await api(bob.accessToken, '/api/two-factor/authenticator', {
    method: 'PUT',
    json: { key: bobKey, token: wrongTotp(bobKey), userVerificationToken: bobUserVerificationToken, masterPasswordHash: mph(BOB) },
  });
  assert.equal(wrongCode.status, 400, JSON.stringify(wrongCode.body));
  assert.deepEqual(await enabledProviders(bob.accessToken), []);

  const forged = await api(bob.accessToken, '/api/two-factor/authenticator', {
    method: 'PUT',
    json: { key: bobKey, token: (await bobCodes.next(bobKey)).code, userVerificationToken: 'forged.token' },
  });
  assert.equal(forged.status, 400, JSON.stringify(forged.body));
  assert.deepEqual(await enabledProviders(bob.accessToken), []);

  const { code } = await bobCodes.next(bobKey);
  const enabled = await api(bob.accessToken, '/api/two-factor/authenticator', {
    method: 'PUT',
    json: { key: bobKey, token: code, userVerificationToken: bobUserVerificationToken, masterPasswordHash: mph(BOB) },
  });
  assert.equal(enabled.status, 200, JSON.stringify(enabled.body));
  assert.equal(pick(enabled.body, 'Enabled'), true);
  assert.equal(pick(enabled.body, 'Key'), bobKey);

  assert.deepEqual(await enabledProviders(bob.accessToken), [0]);
  const status = await api(bob.accessToken, '/api/accounts/totp');
  assert.equal(pick(status.body, 'enabled'), true);
});

test('enabling 2FA revokes existing refresh tokens but not the current access token', async () => {
  const profile = await api(bob.accessToken, '/api/accounts/profile');
  assert.equal(profile.status, 200);
  const refreshed = await refreshGrant(bob.refreshToken);
  assert.notEqual(refreshed.status, 200, JSON.stringify(refreshed.body));
  assert.equal(refreshed.body.error, 'invalid_grant');
});

test('password login without a two-step token answers with the 2FA challenge', async () => {
  const noToken = await passwordLogin(BOB);
  assertTwoFactorChallenge(noToken, ['0'], 'no 2FA fields');
  assert.equal(noToken.body.TwoFactorProviders2['0'], null);

  const providerOnly = await passwordLogin(BOB, { provider: 0 });
  assertTwoFactorChallenge(providerOnly, ['0'], 'provider without token');

  const emptyToken = await passwordLogin(BOB, { provider: 0, token: '' });
  assertTwoFactorChallenge(emptyToken, ['0'], 'empty token');
});

test('a wrong master password is rejected before any 2FA challenge is revealed', async () => {
  const result = await passwordLogin(BOB, { password: 'wrong-password' });
  assert.equal(result.status, 400);
  assert.equal(result.body.error, 'invalid_grant');
  assert.equal(result.body.TwoFactorProviders, undefined);
  assert.equal(result.body.TwoFactorProviders2, undefined);
});

test('a valid TOTP code logs in once; replaying it and wrong codes are rejected', async () => {
  const { code } = await bobCodes.next(bobKey);
  const ok = await passwordLogin(BOB, { provider: 0, token: code });
  assertLoggedIn(ok, 'valid code');
  assert.equal(ok.body.TwoFactorToken, undefined, 'no remember token unless requested');
  const profile = await api(ok.body.access_token, '/api/accounts/profile');
  assert.equal(profile.status, 200);
  assert.equal(pick(profile.body, 'email'), BOB);

  const replay = await passwordLogin(BOB, { provider: 0, token: code });
  assertTwoFactorRejected(replay, 'replayed code');

  const wrong = await passwordLogin(BOB, { provider: 0, token: wrongTotp(bobKey) });
  assertTwoFactorRejected(wrong, 'wrong code');

  const garbage = await passwordLogin(BOB, { provider: 0, token: 'abcdef' });
  assertTwoFactorRejected(garbage, 'non-numeric code');

  // A provider the account has not enabled (1 = email) is not a way around TOTP.
  const otherProvider = await passwordLogin(BOB, { provider: 1, token: '123456' });
  assertTwoFactorRejected(otherProvider, 'provider not enabled');
});

test('remember-me (provider 5) skips 2FA on the same device only', async () => {
  const deviceIdentifier = crypto.randomUUID();
  const { code } = await bobCodes.next(bobKey);
  const first = await passwordLogin(BOB, { provider: 0, token: code, remember: true, deviceIdentifier });
  assertLoggedIn(first, 'login with remember');
  const rememberToken = first.body.TwoFactorToken;
  bobLatestAccessToken = first.body.access_token;
  assert.equal(typeof rememberToken, 'string');
  assert.ok(rememberToken.length > 0);

  const again = await passwordLogin(BOB, { provider: 5, token: rememberToken, deviceIdentifier });
  assertLoggedIn(again, 'remembered device');
  assert.equal(again.body.TwoFactorToken, undefined, 'no new remember token when remember was used');

  // Asking to be remembered again while using the remember token does not mint another one.
  const againRemember = await passwordLogin(BOB, { provider: 5, token: rememberToken, deviceIdentifier, remember: true });
  assertLoggedIn(againRemember, 'remembered device, remember requested');
  assert.equal(againRemember.body.TwoFactorToken, undefined);

  // The token is bound to the device that earned it: elsewhere it only yields the challenge.
  const otherDevice = await passwordLogin(BOB, { provider: 5, token: rememberToken });
  assertTwoFactorChallenge(otherDevice, ['0'], 'remember token from another device');

  const bogus = await passwordLogin(BOB, { provider: 5, token: 'not-a-remember-token', deviceIdentifier });
  assertTwoFactorChallenge(bogus, ['0'], 'unknown remember token');

  // Still needs the password.
  const badPassword = await passwordLogin(BOB, { provider: 5, token: rememberToken, deviceIdentifier, password: 'wrong' });
  assert.equal(badPassword.status, 400);
  assert.equal(badPassword.body.error, 'invalid_grant');
  assert.equal(badPassword.body.access_token, undefined);
});

test('disabling the authenticator requires the master password; afterwards login needs no 2FA', async () => {
  const token = bobLatestAccessToken;

  const noPassword = await api(token, '/api/two-factor/disable', { method: 'PUT', json: { type: 0 } });
  assert.equal(noPassword.status, 400, JSON.stringify(noPassword.body));
  const wrongPassword = await api(token, '/api/two-factor/disable', {
    method: 'PUT',
    json: { type: 0, masterPasswordHash: Buffer.from('wrong').toString('base64') },
  });
  assert.equal(wrongPassword.status, 400, JSON.stringify(wrongPassword.body));
  assert.ok(errorText(wrongPassword.body).length > 0);
  assert.deepEqual(await enabledProviders(token), [0]);
  assertTwoFactorChallenge(await passwordLogin(BOB), ['0'], 'still enabled');

  const disabled = await api(token, '/api/two-factor/disable', { method: 'PUT', json: { type: 0, masterPasswordHash: mph(BOB) } });
  assert.equal(disabled.status, 200, JSON.stringify(disabled.body));
  assert.equal(pick(disabled.body, 'Enabled'), false);
  assert.equal(Number(pick(disabled.body, 'Type')), 0);

  assert.deepEqual(await enabledProviders(token), []);
  const status = await api(token, '/api/accounts/totp');
  assert.equal(pick(status.body, 'enabled'), false);
  assertLoggedIn(await passwordLogin(BOB), 'login after disabling');
});

// ---------------------------------------------------------------------------
// Recovery code (provider 8)

const CAROL = 'carol@example.com';
let carol: Session;
let carolSecret: string;
let carolRecoveryCode: string;
let carolRememberToken: string;
let carolRememberDevice: string;
let carolOldAccessToken: string;
let carolOldRefreshToken: string;
const carolCodes = new TotpCodes();

test('the web vault can enable TOTP with its own secret via /api/accounts/totp', async () => {
  carol = await client.registerAndLogin(CAROL);
  carolSecret = randomBase32Secret();

  const wrongPassword = await api(carol.accessToken, '/api/accounts/totp', {
    method: 'PUT',
    json: { enabled: true, secret: carolSecret, token: wrongTotp(carolSecret), masterPasswordHash: Buffer.from('nope').toString('base64') },
  });
  assert.equal(wrongPassword.status, 400);
  const wrongCode = await api(carol.accessToken, '/api/accounts/totp', {
    method: 'PUT',
    json: { enabled: true, secret: carolSecret, token: wrongTotp(carolSecret), masterPasswordHash: mph(CAROL) },
  });
  assert.equal(wrongCode.status, 400);
  assert.deepEqual(await enabledProviders(carol.accessToken), []);

  const { code } = await carolCodes.next(carolSecret);
  const enabled = await api(carol.accessToken, '/api/accounts/totp', {
    method: 'PUT',
    json: { enabled: true, secret: carolSecret, token: code, masterPasswordHash: mph(CAROL) },
  });
  assert.equal(enabled.status, 200, JSON.stringify(enabled.body));
  assert.equal(pick(enabled.body, 'enabled'), true);
  assert.match(pick(enabled.body, 'recoveryCode'), /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
  assert.deepEqual(await enabledProviders(carol.accessToken), [0]);
});

test('the recovery code is only handed out against the master password', async () => {
  const missing = await api(carol.accessToken, '/api/two-factor/get-recover', { method: 'POST', json: {} });
  assert.equal(missing.status, 400);
  const wrong = await api(carol.accessToken, '/api/two-factor/get-recover', {
    method: 'POST',
    json: { masterPasswordHash: Buffer.from('nope').toString('base64') },
  });
  assert.equal(wrong.status, 400);

  const recover = await api(carol.accessToken, '/api/two-factor/get-recover', { method: 'POST', json: { masterPasswordHash: mph(CAROL) } });
  assert.equal(recover.status, 200, JSON.stringify(recover.body));
  carolRecoveryCode = pick(recover.body, 'Code');
  assert.match(carolRecoveryCode, /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);

  // Same code through the web vault's route; stable until used.
  const again = await api(carol.accessToken, '/api/accounts/totp/recovery-code', { method: 'POST', json: { masterPasswordHash: mph(CAROL) } });
  assert.equal(again.status, 200);
  assert.equal(pick(again.body, 'Code'), carolRecoveryCode);
});

test('logging in with the recovery code turns 2FA off, rotates the code and ends other sessions', async () => {
  // A remembered device and a live session from before the recovery.
  const { code } = await carolCodes.next(carolSecret);
  const before = await passwordLogin(CAROL, { provider: 0, token: code, remember: true });
  assertLoggedIn(before, 'session before recovery');
  carolRememberToken = before.body.TwoFactorToken;
  carolRememberDevice = before.deviceIdentifier;
  carolOldAccessToken = before.body.access_token;
  carolOldRefreshToken = before.body.refresh_token;
  assert.equal(typeof carolRememberToken, 'string');
  assert.equal(typeof carolOldRefreshToken, 'string');

  const wrong = await passwordLogin(CAROL, { provider: 8, token: 'AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH' });
  assertTwoFactorRejected(wrong, 'wrong recovery code');

  // Recovery code needs the password too.
  const badPassword = await passwordLogin(CAROL, { provider: 8, token: carolRecoveryCode, password: 'wrong' });
  assert.equal(badPassword.status, 400);
  assert.equal(badPassword.body.access_token, undefined);

  // Clients may send the code without spaces / in lower case.
  const recovered = await passwordLogin(CAROL, {
    provider: 8,
    token: carolRecoveryCode.replace(/ /g, '').toLowerCase(),
    remember: true,
  });
  assertLoggedIn(recovered, 'recovery code login');
  assert.equal(recovered.body.TwoFactorToken, undefined, 'recovery login does not remember the device');
  const token = recovered.body.access_token;

  assert.deepEqual(await enabledProviders(token), []);
  assertLoggedIn(await passwordLogin(CAROL), 'login without 2FA after recovery');

  // Sessions from before the recovery are gone.
  const oldAccess = await api(carolOldAccessToken, '/api/accounts/profile');
  assert.equal(oldAccess.status, 401);
  const oldRefresh = await refreshGrant(carolOldRefreshToken);
  assert.notEqual(oldRefresh.status, 200, JSON.stringify(oldRefresh.body));
  assert.equal(oldRefresh.body.error, 'invalid_grant');

  // A new recovery code replaces the used one.
  const next = await api(token, '/api/two-factor/get-recover', { method: 'POST', json: { masterPasswordHash: mph(CAROL) } });
  assert.equal(next.status, 200);
  const nextCode = pick(next.body, 'Code');
  assert.match(nextCode, /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
  assert.notEqual(nextCode, carolRecoveryCode);
});

test('after recovery, 2FA can be enabled again and is enforced', async () => {
  const login = await passwordLogin(CAROL);
  assertLoggedIn(login, 'login');
  carol = { ...carol, accessToken: login.body.access_token, refreshToken: login.body.refresh_token };
  carolSecret = await enableAuthenticator(carol, carolCodes);
  assertTwoFactorChallenge(await passwordLogin(CAROL), ['0'], 're-enabled');
  // The used recovery code does not work any more.
  assertTwoFactorRejected(await passwordLogin(CAROL, { provider: 8, token: carolRecoveryCode }), 'used recovery code');
});

test(
  'remember-me tokens issued before a recovery-code reset no longer skip 2FA',
  async () => {
    const result = await passwordLogin(CAROL, { provider: 5, token: carolRememberToken, deviceIdentifier: carolRememberDevice });
    assertTwoFactorChallenge(result, ['0'], 'stale remember token');
  },
);

test('/identity/accounts/recover-2fa turns 2FA off with email, password and recovery code', async () => {
  const current = await api(carol.accessToken, '/api/two-factor/get-recover', { method: 'POST', json: { masterPasswordHash: mph(CAROL) } });
  assert.equal(current.status, 200);
  const recoveryCode = pick(current.body, 'Code');

  const recover = (body: Record<string, string>) =>
    client.fetch('/identity/accounts/recover-2fa', { method: 'POST', json: body }).then(async (r) => ({ status: r.status, body: await r.json() }));

  const wrongCode = await recover({ email: CAROL, masterPasswordHash: mph(CAROL), recoveryCode: 'AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH' });
  assert.equal(wrongCode.status, 400);
  const wrongPassword = await recover({ email: CAROL, masterPasswordHash: Buffer.from('nope').toString('base64'), recoveryCode });
  assert.equal(wrongPassword.status, 400);
  assertTwoFactorChallenge(await passwordLogin(CAROL), ['0'], 'still enabled after failed recoveries');

  const ok = await recover({ email: CAROL, masterPasswordHash: mph(CAROL), recoveryCode });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(pick(ok.body, 'twoFactorEnabled'), false);
  const newCode = pick(ok.body, 'newRecoveryCode');
  assert.match(newCode, /^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
  assert.notEqual(newCode, recoveryCode);

  assertLoggedIn(await passwordLogin(CAROL), 'login after recover-2fa');
  // It also ended the session that existed before.
  assert.equal((await api(carol.accessToken, '/api/accounts/profile')).status, 401);
});

// ---------------------------------------------------------------------------
// YubiKey OTP (provider 3)

const DAVE = 'dave@example.com';
let dave: Session;
let davePublicId: string;

test('only the admin can store the Yubico API credentials', async () => {
  dave = await client.registerAndLogin(DAVE);

  const notAdmin = await api(dave.accessToken, '/api/two-factor/yubikey/config', {
    method: 'PUT',
    json: { masterPasswordHash: mph(DAVE), yubicoClientId: yubico.clientId, yubicoSecretKey: yubico.secretKey },
  });
  assert.equal(notAdmin.status, 403);

  const wrongPassword = await api(alice.accessToken, '/api/two-factor/yubikey/config', {
    method: 'PUT',
    json: { masterPasswordHash: Buffer.from('nope').toString('base64'), yubicoClientId: yubico.clientId, yubicoSecretKey: yubico.secretKey },
  });
  assert.equal(wrongPassword.status, 400);

  const saved = await api(alice.accessToken, '/api/two-factor/yubikey/config', {
    method: 'PUT',
    json: { masterPasswordHash: mph('alice@example.com'), yubicoClientId: yubico.clientId, yubicoSecretKey: yubico.secretKey },
  });
  assert.equal(saved.status, 200, JSON.stringify(saved.body));
  assert.equal(pick(saved.body, 'YubicoConfigured'), true);
});

test('registering a YubiKey validates an OTP with the Yubico service', async () => {
  const settings = await api(dave.accessToken, '/api/two-factor/get-yubikey', { method: 'POST', json: { masterPasswordHash: mph(DAVE) } });
  assert.equal(settings.status, 200, JSON.stringify(settings.body));
  assert.equal(pick(settings.body, 'Enabled'), false);
  assert.equal(pick(settings.body, 'YubicoConfigured'), true);
  // Only the admin gets to see the API secret.
  assert.equal(pick(settings.body, 'YubicoSecretKey'), undefined);

  const noPassword = await api(dave.accessToken, '/api/two-factor/get-yubikey', { method: 'POST', json: {} });
  assert.equal(noPassword.status, 400);

  davePublicId = yubiKeyPublicId();

  const wrongPassword = await api(dave.accessToken, '/api/two-factor/yubikey', {
    method: 'PUT',
    json: { key1: yubiKeyOtp(davePublicId), nfc: true, masterPasswordHash: Buffer.from('nope').toString('base64') },
  });
  assert.equal(wrongPassword.status, 400);

  const rejectedOtp = yubiKeyOtp(davePublicId);
  yubico.statusFor.set(rejectedOtp, 'BAD_OTP');
  const rejected = await api(dave.accessToken, '/api/two-factor/yubikey', {
    method: 'PUT',
    json: { key1: rejectedOtp, nfc: true, masterPasswordHash: mph(DAVE) },
  });
  assert.equal(rejected.status, 400);

  const notModhex = await api(dave.accessToken, '/api/two-factor/yubikey', {
    method: 'PUT',
    json: { key1: 'x'.repeat(44), nfc: true, masterPasswordHash: mph(DAVE) },
  });
  assert.equal(notModhex.status, 400);
  assert.deepEqual(await enabledProviders(dave.accessToken), []);

  const otp = yubiKeyOtp(davePublicId);
  const before = yubico.requests.length;
  const saved = await api(dave.accessToken, '/api/two-factor/yubikey', {
    method: 'PUT',
    json: { key1: otp, key2: '', key3: '', key4: '', key5: '', nfc: true, masterPasswordHash: mph(DAVE) },
  });
  assert.equal(saved.status, 200, JSON.stringify(saved.body));
  assert.equal(pick(saved.body, 'Enabled'), true);
  assert.equal(pick(saved.body, 'Key1'), davePublicId);
  assert.equal(pick(saved.body, 'Nfc'), true);

  const calls = yubico.requests.slice(before);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].otp, otp);
  assert.equal(calls[0].id, yubico.clientId);
  assert.equal(calls[0].signatureValid, true, 'server signs its validation request with the API secret');
  assert.ok(calls[0].nonce.length >= 16);

  assert.deepEqual(await enabledProviders(dave.accessToken), [3]);
});

test('password login for a YubiKey account challenges with provider 3 and its NFC flag', async () => {
  const challenge = await passwordLogin(DAVE);
  assertTwoFactorChallenge(challenge, ['3'], 'yubikey challenge');
  assert.deepEqual(challenge.body.TwoFactorProviders2['3'], { Nfc: true });
});

test('a valid YubiKey OTP logs in; rejected, replayed, forged or foreign OTPs do not', async () => {
  const otp = yubiKeyOtp(davePublicId);
  assertLoggedIn(await passwordLogin(DAVE, { provider: 3, token: otp }), 'valid otp');

  // The Yubico service reports the second use of an OTP as REPLAYED_OTP.
  assertTwoFactorRejected(await passwordLogin(DAVE, { provider: 3, token: otp }), 'replayed otp');

  const badOtp = yubiKeyOtp(davePublicId);
  yubico.statusFor.set(badOtp, 'BAD_OTP');
  assertTwoFactorRejected(await passwordLogin(DAVE, { provider: 3, token: badOtp }), 'BAD_OTP');

  const replayed = yubiKeyOtp(davePublicId);
  yubico.statusFor.set(replayed, 'REPLAYED_OTP');
  assertTwoFactorRejected(await passwordLogin(DAVE, { provider: 3, token: replayed }), 'REPLAYED_OTP');

  const forged = yubiKeyOtp(davePublicId);
  yubico.forgeSignatureFor.add(forged);
  assertTwoFactorRejected(await passwordLogin(DAVE, { provider: 3, token: forged }), 'response with a bad signature');

  // An OTP from a key that is not registered is refused without asking Yubico.
  const before = yubico.requests.length;
  assertTwoFactorRejected(await passwordLogin(DAVE, { provider: 3, token: yubiKeyOtp(yubiKeyPublicId()) }), 'unregistered key');
  assert.equal(yubico.requests.length, before);

  // A TOTP code is not accepted for an account that only has a YubiKey.
  assertTwoFactorRejected(await passwordLogin(DAVE, { provider: 0, token: '123456' }), 'totp without authenticator');

  assertLoggedIn(await passwordLogin(DAVE, { provider: 3, token: yubiKeyOtp(davePublicId) }), 'fresh otp after failures');
});

test('disabling the YubiKey requires the master password; afterwards login needs no 2FA', async () => {
  const login = await passwordLogin(DAVE, { provider: 3, token: yubiKeyOtp(davePublicId) });
  assertLoggedIn(login, 'session');
  const token = login.body.access_token;

  const wrong = await api(token, '/api/two-factor/disable', {
    method: 'PUT',
    json: { type: 3, masterPasswordHash: Buffer.from('nope').toString('base64') },
  });
  assert.equal(wrong.status, 400);
  assert.deepEqual(await enabledProviders(token), [3]);

  const disabled = await api(token, '/api/two-factor/disable', { method: 'PUT', json: { type: 3, masterPasswordHash: mph(DAVE) } });
  assert.equal(disabled.status, 200, JSON.stringify(disabled.body));
  assert.equal(pick(disabled.body, 'Enabled'), false);
  assert.deepEqual(await enabledProviders(token), []);
  assertLoggedIn(await passwordLogin(DAVE), 'login after disabling yubikey');
});
