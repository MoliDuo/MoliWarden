// Generates the legacy ("v1") fixture: a database produced by the CURRENT
// server code that exercises every stored feature, plus the S3 objects it
// references, an admin backup export and a manifest describing it all.
//
//   npx tsx tests/legacy-fixture/generate.ts
//
// Data is created through the HTTP API wherever possible. Direct SQL is used
// only for (a) stored formats the current code still reads but can no longer
// write (see applyLegacyVariants) and (b) clock adjustments
// that keep the fixture usable after it is committed (see applyClockAdjustments).
// Both are listed in manifest.json.
import { createHash, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { unzipSync, zipSync } from 'fflate';
import {
  FIXTURE_BUCKET,
  FIXTURE_DATABASE_URL,
  FIXTURE_DIR,
  FIXTURE_JWT_SECRET,
  Http,
  PG_CONTAINER,
  WEBAUTHN_RP_ID,
  WEBAUTHN_RP_NAME,
  YUBICO_CLIENT_ID,
  YUBICO_SECRET_KEY,
  assert,
  databaseName,
  dotNetGuidBytes,
  emptyBucket,
  enc,
  ensureBucketExists,
  ensureDatabase,
  getObject,
  importServerModule,
  prepareServerRoot,
  serverCommit,
  SERVER_ROOT,
  jwtClaims,
  listObjectKeys,
  masterPasswordHash,
  passwordGrantFields,
  passwordString,
  rsaEnc,
  sleep,
  startFixedYubicoMock,
  withDb,
  yubiKeyOtp,
} from './common';
import { SoftAuthenticator, b64url, type SoftCredential } from '../webauthn-soft';
import { TotpCodes } from '../totp';

// The v1 push relay reads process.env directly (not the env handed to
// createNodeHandler); keep it from calling the real Bitwarden relay.
process.env.PUSH_RELAY_DISABLED = '1';

// tests/helpers.ts reads TEST_DATABASE_URL when it is first imported.
process.env.TEST_DATABASE_URL = FIXTURE_DATABASE_URL;

// ---------------------------------------------------------------------------
// Fixed inputs

const E = {
  admin: 'admin@fixture.example',
  vault: 'vault@fixture.example',
  argon: 'argon@fixture.example',
  totp: 'totp@fixture.example',
  yubikey: 'yubikey@fixture.example',
  webauthn2fa: 'webauthn2fa@fixture.example',
  passkey: 'passkey@fixture.example',
  manager: 'manager@fixture.example',
  custom: 'custom@fixture.example',
  banned: 'banned@fixture.example',
  legacyRawHash: 'legacy-rawhash@fixture.example',
  legacyApiKey: 'legacy-apikey@fixture.example',
  legacyDomains: 'legacy-domains@fixture.example',
  legacyTotp: 'legacy-totp@fixture.example',
  legacyYubikey: 'legacy-yubikey@fixture.example',
  legacyKdf: 'legacy-kdf@fixture.example',
  legacyStatus: 'legacy-status@fixture.example',
  legacySession: 'legacy-session@fixture.example',
  legacyCipher: 'legacy-cipher@fixture.example',
} as const;
type AccountKey = keyof typeof E;

const TOTP_SECRET = 'JBSWY3DPEHPK3PXPMOLIWARDENFIXTR';
const YUBIKEY_PUBLIC_ID = 'cccccbhjklnr';
const LEGACY_API_KEY_SECRET = 'LegacyFixtureApiKeySecret0001';
const SEND_PASSWORD_HASH = Buffer.from('send-password'.padEnd(32, '#')).toString('base64');
const FAR_FUTURE_MS = Date.UTC(2099, 0, 1);
const FAR_FUTURE_ISO = new Date(FAR_FUTURE_MS).toISOString();

// Deterministic v4-shaped UUID for device identifiers.
function fixedUuid(label: string): string {
  const h = createHash('sha256').update(`legacy-fixture:${label}`).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

let ipCounter = 0;
function nextIp(): string {
  ipCounter += 1;
  return `10.77.${Math.floor(ipCounter / 250) % 250}.${(ipCounter % 250) + 1}`;
}

function inDays(days: number): string {
  return new Date(Date.now() + days * 86400000).toISOString();
}

// ---------------------------------------------------------------------------
// Manifest bookkeeping

interface Session {
  key: AccountKey;
  email: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  deviceIdentifier: string;
}

const manifest: any = {
  formatVersion: 1,
  description: 'Legacy (v1) MoliWarden fixture. See README.md.',
  generatedAt: new Date().toISOString(),
  generatedWith: '',
  server: {
    jwtSecret: FIXTURE_JWT_SECRET,
    webauthnRpId: WEBAUTHN_RP_ID,
    webauthnRpName: WEBAUTHN_RP_NAME,
    yubico: { clientId: YUBICO_CLIENT_ID, secretKey: YUBICO_SECRET_KEY },
    s3Bucket: FIXTURE_BUCKET,
    env: { SHOW_PASSWORD_HINT: '1' },
    note: 'Start the server with JWT_SECRET above, YUBICO_VALIDATION_URLS pointing at a mock that uses the yubico secret above (common.ts startFixedYubicoMock) and reach it via http://127.0.0.1:<port> (passkeys are bound to RP id 127.0.0.1).',
  },
  accounts: {} as Record<string, any>,
  organizations: {} as Record<string, any>,
  features: {} as Record<string, any>,
  legacyVariants: [] as any[],
  clockAdjustments: [] as any[],
  expectations: {} as Record<string, any>,
};

function account(key: AccountKey): any {
  manifest.accounts[key] ??= { email: E[key] };
  return manifest.accounts[key];
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  prepareServerRoot();
  manifest.generatedWith = serverCommit();
  await ensureDatabase(FIXTURE_DATABASE_URL);
  await ensureBucketExists(FIXTURE_BUCKET);
  await emptyBucket(FIXTURE_BUCKET);

  const yubico = await startFixedYubicoMock();
  const helpers = await importServerModule<{
    startTestServer(options: { env?: Record<string, string> }): Promise<{ baseUrl: string; close(): Promise<void> }>;
  }>('tests/helpers.ts');
  const server = await helpers.startTestServer({
    env: {
      S3_BUCKET: FIXTURE_BUCKET,
      YUBICO_VALIDATION_URLS: yubico.url,
      WEBAUTHN_RP_NAME,
      SHOW_PASSWORD_HINT: '1',
    },
  });
  const http = new Http(server.baseUrl);
  const origin = server.baseUrl;
  console.log(`server (${SERVER_ROOT}) at ${server.baseUrl}, database ${databaseName(FIXTURE_DATABASE_URL)}, bucket ${FIXTURE_BUCKET}`);

  try {
    await populate(http, origin);
  } finally {
    await server.close();
    await yubico.close();
  }

  await writeOutputs();
  console.log('done');
}

// ---------------------------------------------------------------------------
// Population through the HTTP API

async function populate(http: Http, origin: string): Promise<void> {
  const sessions = {} as Record<AccountKey, Session>;
  const api = (s: Session, path: string, init: RequestInit & { json?: unknown } = {}) => http.ok(path, { ...init, token: s.accessToken });
  const call = (s: Session, path: string, init: RequestInit & { json?: unknown } = {}) => http.call(path, { ...init, token: s.accessToken });
  const mph = (key: AccountKey) => masterPasswordHash(E[key]);

  async function login(
    key: AccountKey,
    options: { device: string; clientId?: string; deviceType?: number; deviceName?: string; extra?: Record<string, string>; headers?: Record<string, string> },
  ): Promise<{ session: Session; body: any; headers: Headers }> {
    const deviceIdentifier = fixedUuid(`${key}:${options.device}`);
    const result = await http.token(
      passwordGrantFields(E[key], {
        masterPasswordHash: mph(key),
        deviceIdentifier,
        clientId: options.clientId,
        deviceType: options.deviceType,
        deviceName: options.deviceName ?? options.device,
        extra: options.extra,
      }),
      options.headers,
    );
    if (result.status !== 200) throw new Error(`login ${E[key]} (${options.device}) -> ${result.status}: ${JSON.stringify(result.body)}`);
    const session: Session = {
      key,
      email: E[key],
      userId: jwtClaims(result.body.access_token).sub,
      accessToken: result.body.access_token,
      refreshToken: result.body.refresh_token,
      deviceIdentifier,
    };
    return { session, body: result.body, headers: result.headers };
  }

  function recordDevice(key: AccountKey, device: string, extra: Record<string, unknown>): void {
    const acc = account(key);
    acc.devices ??= {};
    acc.devices[device] = { identifier: fixedUuid(`${key}:${device}`), ...extra };
  }

  // --- registration --------------------------------------------------------

  // The admin gets a real RSA public key so the backup-settings portable
  // envelope (RSA-OAEP wrapped for every active admin) is actually populated.
  const adminRsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const adminPublicKey = adminRsa.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  async function mintInvite(hours = 24): Promise<string> {
    const invite = await api(sessions.admin, '/api/admin/invites', {
      method: 'POST',
      json: { expiresInHours: hours, masterPasswordHash: mph('admin') },
    });
    return invite.code ?? invite.invite?.code;
  }

  async function register(
    key: AccountKey,
    options: { kdf?: number; kdfIterations?: number; kdfMemory?: number; kdfParallelism?: number; hint?: string; publicKey?: string } = {},
  ): Promise<void> {
    const inviteCode = sessions.admin ? await mintInvite() : undefined;
    const email = E[key];
    const publicKey = options.publicKey ?? Buffer.from(`public-key-${email}`).toString('base64');
    await http.ok('/api/accounts/register', {
      method: 'POST',
      headers: { Origin: origin, 'X-Forwarded-For': nextIp() },
      json: {
        email,
        name: key,
        masterPasswordHash: mph(key),
        masterPasswordHint: options.hint,
        key: enc(`user-key-${key}`),
        keys: { publicKey, encryptedPrivateKey: enc(`private-key-${key}`) },
        kdf: options.kdf ?? 0,
        kdfIterations: options.kdfIterations ?? 600000,
        kdfMemory: options.kdfMemory,
        kdfParallelism: options.kdfParallelism,
        inviteCode,
      },
    });
    const acc = account(key);
    acc.passwordString = passwordString(email);
    acc.masterPasswordHash = mph(key);
    acc.kdf = {
      type: options.kdf ?? 0,
      iterations: options.kdfIterations ?? 600000,
      memory: options.kdfMemory ?? null,
      parallelism: options.kdfParallelism ?? null,
    };
    acc.userKey = enc(`user-key-${key}`);
    acc.publicKey = publicKey;
    if (options.hint) acc.masterPasswordHint = options.hint;
    if (inviteCode) acc.inviteCode = inviteCode;
  }

  await register('admin', { publicKey: adminPublicKey });
  sessions.admin = (await login('admin', { device: 'cli', clientId: 'cli', deviceType: 25 })).session;
  Object.assign(account('admin'), {
    userId: sessions.admin.userId,
    role: 'admin',
    covers: ['instance admin (first user)', 'real RSA public key -> backup settings portable wraps', 'yubico API config', 'audit log settings', 'invites', 'backup settings', 'org owner'],
    rsaPrivateKeyPkcs8: adminRsa.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  });
  recordDevice('admin', 'cli', { type: 25, clientId: 'cli' });

  await register('vault', { kdfIterations: 350000, hint: 'the usual one' });
  await register('argon', { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
  for (const key of ['totp', 'yubikey', 'webauthn2fa', 'passkey', 'manager', 'custom', 'banned', 'legacyRawHash', 'legacyApiKey', 'legacyDomains', 'legacyTotp', 'legacyYubikey', 'legacyKdf', 'legacyStatus', 'legacySession', 'legacyCipher'] as const) {
    await register(key);
  }
  for (const key of Object.keys(E) as AccountKey[]) {
    if (sessions[key]) continue;
    sessions[key] = (await login(key, { device: 'cli', clientId: 'cli', deviceType: 25 })).session;
    account(key).userId = sessions[key].userId;
    recordDevice(key, 'cli', { type: 25, clientId: 'cli' });
  }
  Object.assign(account('vault'), {
    covers: ['PBKDF2 350000 + master password hint', 'personal vault: folders, cipher types 1-8, favorite/archived/deleted/reprompt/cipher key/key-added marker', 'attachments', 'sends (all variants)', 'equivalent domains', 'personal API key (rotated)', 'devices of several types, push token, device keys, device note', 'web (cookie) and mobile refresh tokens', 'auth requests', 'org user member'],
  });
  Object.assign(account('argon'), { covers: ['Argon2id kdf (3 iterations, 64 MiB, parallelism 4)', 'org admin (accessAll)', 'owner of a second organization'] });

  // --- admin settings ------------------------------------------------------

  await api(sessions.admin, '/api/two-factor/yubikey/config', {
    method: 'PUT',
    json: { masterPasswordHash: mph('admin'), yubicoClientId: YUBICO_CLIENT_ID, yubicoSecretKey: YUBICO_SECRET_KEY },
  });
  const logSettings = await api(sessions.admin, '/api/admin/logs/settings', { method: 'PUT', json: { retentionDays: 365 } });
  manifest.features.auditLogSettings = { expected: { retentionDays: logSettings.retentionDays, maxEntries: logSettings.maxEntries } };

  // Invites: every registration above used one; add an unused, an expired
  // (see clock adjustments) and a deleted one.
  const unusedInvite = await mintInvite(24 * 30);
  const expiredInvite = await mintInvite(1);
  const deletedInvite = await mintInvite(1);
  await http.ok(`/api/admin/invites/${deletedInvite}`, { method: 'DELETE', token: sessions.admin.accessToken, json: { masterPasswordHash: mph('admin') } });
  manifest.features.invites = { unused: unusedInvite, expired: expiredInvite, deletedAndGone: deletedInvite };

  // --- vault: devices and sessions -------------------------------------------

  const vault = sessions.vault;
  const android = await login('vault', { device: 'android', clientId: 'mobile', deviceType: 0, deviceName: 'Pixel 9' });
  await api(android.session, `/api/devices/identifier/${android.session.deviceIdentifier}/token`, {
    method: 'PUT',
    json: { pushToken: 'fixture-fcm-push-token-0001' },
  });
  recordDevice('vault', 'android', { type: 0, clientId: 'mobile', pushToken: 'fixture-fcm-push-token-0001', refreshToken: android.session.refreshToken });

  const web = await login('vault', { device: 'web', clientId: 'web', deviceType: 9, deviceName: 'chrome', headers: { 'X-MoliWarden-Web-Session': '1' } });
  const cookie = web.headers.getSetCookie().find((c) => c.startsWith('moliwarden_web_refresh='));
  assert(cookie, 'web session refresh cookie');
  const webRefreshToken = cookie.split(';')[0].slice('moliwarden_web_refresh='.length);
  recordDevice('vault', 'web', { type: 9, clientId: 'web', refreshTokenCookie: webRefreshToken });

  const extension = await login('vault', { device: 'extension', clientId: 'browser', deviceType: 2, deviceName: 'chrome-extension' });
  recordDevice('vault', 'extension', { type: 2, clientId: 'browser', refreshToken: extension.session.refreshToken });

  const desktop = await login('vault', { device: 'desktop', clientId: 'desktop', deviceType: 6, deviceName: 'windows' });
  await api(desktop.session, `/api/devices/${desktop.session.deviceIdentifier}/keys`, {
    method: 'PUT',
    json: { encryptedUserKey: rsaEnc('device-user-key'), encryptedPublicKey: enc('device-public-key'), encryptedPrivateKey: enc('device-private-key') },
  });
  await api(desktop.session, `/api/devices/${desktop.session.deviceIdentifier}/name`, { method: 'PUT', json: { name: 'Work laptop' } });
  recordDevice('vault', 'desktop', { type: 6, clientId: 'desktop', trustedDeviceKeys: true, deviceNote: 'Work laptop', refreshToken: desktop.session.refreshToken });
  account('vault').refreshTokens = { mobile: android.session.refreshToken, web: webRefreshToken, cli: vault.refreshToken };

  // --- vault: folders and ciphers --------------------------------------------

  const folders: Record<string, string> = {};
  for (const name of ['personal', 'work', 'empty']) {
    folders[name] = (await api(vault, '/api/folders', { method: 'POST', json: { name: enc(`folder-${name}`) } })).id;
  }

  const ciphers: Record<string, string> = {};
  const cipherBase = (label: string) => ({ name: enc(`name-${label}`), notes: enc(`notes-${label}`), favorite: false, folderId: null, reprompt: 0 });
  const personalCiphers: Array<[string, Record<string, unknown>]> = [
    ['login', {
      type: 1,
      favorite: true,
      folderId: folders.personal,
      login: {
        username: enc('username'),
        password: enc('password'),
        totp: enc('totp-uri'),
        passwordRevisionDate: '2025-01-02T03:04:05.000Z',
        uris: [
          { uri: enc('uri-domain'), uriChecksum: enc('uri-domain-checksum'), match: 0 },
          { uri: enc('uri-exact'), match: 3 },
          { uri: enc('uri-default'), match: null },
        ],
        fido2Credentials: [{
          credentialId: enc('fido2-credential-id'),
          keyType: enc('public-key'),
          keyAlgorithm: enc('ECDSA'),
          keyCurve: enc('P-256'),
          keyValue: enc('fido2-key-value'),
          rpId: enc('fido2.example'),
          userHandle: enc('fido2-user-handle'),
          userName: enc('fido2-user'),
          counter: enc('0'),
          rpName: enc('Fido2 Example'),
          userDisplayName: enc('Fido2 User'),
          discoverable: enc('true'),
          creationDate: '2025-03-04T05:06:07.000Z',
        }],
      },
      fields: [
        { name: enc('field-text'), value: enc('field-text-value'), type: 0, linkedId: null },
        { name: enc('field-hidden'), value: enc('field-hidden-value'), type: 1, linkedId: null },
        { name: enc('field-boolean'), value: enc('true'), type: 2, linkedId: null },
        { name: enc('field-linked'), value: null, type: 3, linkedId: 100 },
      ],
      passwordHistory: [
        { password: enc('old-password-1'), lastUsedDate: '2024-12-01T00:00:00.000Z' },
        { password: enc('old-password-2'), lastUsedDate: '2025-01-01T00:00:00.000Z' },
      ],
    }],
    ['note', { type: 2, folderId: folders.work, secureNote: { type: 0 } }],
    ['card', {
      type: 3,
      reprompt: 1,
      card: { cardholderName: enc('holder'), brand: enc('brand'), number: enc('number'), expMonth: enc('month'), expYear: enc('year'), code: enc('code') },
    }],
    ['identity', {
      type: 4,
      key: enc('identity-cipher-key'),
      identity: {
        title: enc('title'), firstName: enc('first'), middleName: enc('middle'), lastName: enc('last'), address1: enc('address1'),
        address2: enc('address2'), address3: enc('address3'), city: enc('city'), state: enc('state'), postalCode: enc('postal'),
        country: enc('country'), company: enc('company'), email: enc('email'), phone: enc('phone'), ssn: enc('ssn'),
        username: enc('id-username'), passportNumber: enc('id-passport'), licenseNumber: enc('id-license'),
      },
    }],
    ['ssh-key', { type: 5, sshKey: { privateKey: enc('ssh-private'), publicKey: enc('ssh-public'), keyFingerprint: enc('ssh-fingerprint') } }],
    ['bank-account', { type: 6, bankAccount: { bankName: enc('bank'), accountNumber: enc('account'), routingNumber: enc('routing'), iban: enc('iban'), swiftCode: enc('swift') } }],
    ['drivers-license', { type: 7, driversLicense: { firstName: enc('dl-first'), lastName: enc('dl-last'), licenseNumber: enc('license'), issuingCountry: enc('dl-country') } }],
    ['passport', { type: 8, passport: { surname: enc('surname'), givenName: enc('given'), passportNumber: enc('passport'), nationality: enc('nationality') } }],
  ];
  for (const [label, payload] of personalCiphers) {
    ciphers[label] = (await api(vault, '/api/ciphers', { method: 'POST', json: { ...cipherBase(label), ...payload } })).id;
  }
  // Archived, soft-deleted (trash), and one both archived and in a folder.
  await api(vault, `/api/ciphers/${ciphers['ssh-key']}/archive`, { method: 'PUT' });
  await http.ok(`/api/ciphers/${ciphers['bank-account']}/delete`, { method: 'PUT', token: vault.accessToken });

  // The iOS "key added" path: an existing item gets a cipher key on update,
  // which leaves the internal keyAddedFromRevision marker in ciphers.data.
  const keyAdded = await api(vault, '/api/ciphers', { method: 'POST', json: { ...cipherBase('key-added'), type: 1, login: { username: enc('ka-user'), password: enc('ka-pass') } } });
  await sleep(1100);
  await api(vault, `/api/ciphers/${keyAdded.id}`, {
    method: 'PUT',
    json: { ...cipherBase('key-added'), type: 1, login: { username: enc('ka-user'), password: enc('ka-pass') }, key: enc('key-added-cipher-key'), lastKnownRevisionDate: keyAdded.revisionDate },
  });
  ciphers['key-added'] = keyAdded.id;

  // --- attachments ---------------------------------------------------------

  const attachments: Record<string, any> = {};
  async function attach(s: Session, cipherId: string, label: string, content: Buffer): Promise<void> {
    const meta = await api(s, `/api/ciphers/${cipherId}/attachment/v2`, {
      method: 'POST',
      json: { key: enc(`attachment-key-${label}`), fileName: enc(`attachment-name-${label}`), fileSize: content.length },
    });
    const uploadUrl = new URL(meta.url);
    const upload = await http.fetch(uploadUrl.pathname + uploadUrl.search, {
      method: 'PUT',
      headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(content.length) },
      body: new Uint8Array(content),
    });
    assert(upload.status === 201, `attachment upload ${label}: ${upload.status} ${await upload.text()}`);
    attachments[label] = { cipherId, attachmentId: meta.attachmentId, objectKey: `${cipherId}/${meta.attachmentId}`, size: content.length, sha256: createHash('sha256').update(content).digest('hex'), owner: s.key };
  }
  await attach(vault, ciphers.login, 'login-text', Buffer.from('encrypted-attachment-bytes:login-text\n'.repeat(8)));
  await attach(vault, ciphers.login, 'login-binary', Buffer.from(Array.from({ length: 512 }, (_, i) => (i * 37 + 11) & 0xff)));
  await attach(vault, ciphers.note, 'note', Buffer.from('encrypted-attachment-bytes:note'));

  // --- sends -----------------------------------------------------------------

  const sends: Record<string, any> = {};
  const accessV1 = (accessId: string, body: Record<string, unknown> = {}) =>
    http.call(`/api/sends/access/${accessId}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: body });
  const textSend = (label: string, extra: Record<string, unknown> = {}) => ({
    type: 0,
    name: enc(`send-name-${label}`),
    notes: enc(`send-notes-${label}`),
    key: enc(`send-key-${label}`),
    text: { text: enc(`send-text-${label}`), hidden: false },
    deletionDate: inDays(7),
    expirationDate: null,
    maxAccessCount: null,
    disabled: false,
    hideEmail: false,
    password: null,
    ...extra,
  });
  async function createSend(label: string, extra: Record<string, unknown>, expected: Record<string, unknown>): Promise<any> {
    const send = await api(vault, '/api/sends', { method: 'POST', json: textSend(label, extra) });
    sends[label] = { id: send.id, accessId: send.accessId, expected };
    return send;
  }
  const accessed = await createSend('text-accessed', { maxAccessCount: 10 }, { type: 0, accessCount: 2, maxAccessCount: 10, authType: 2 });
  for (let i = 0; i < 2; i++) assert((await accessV1(accessed.accessId)).status === 200, 'send access');
  await createSend('text-password', { password: SEND_PASSWORD_HASH }, { type: 0, authType: 1, passwordHashB64: SEND_PASSWORD_HASH, storedFormat: 'client hash as sent, no salt' });
  // A non-hash password is salted and PBKDF2-hashed by the server (password_salt/password_iterations set).
  await createSend('text-password-server-hashed', { password: 'fixture send password' }, { type: 0, authType: 1, password: 'fixture send password', storedFormat: 'server PBKDF2 with salt + iterations' });
  await createSend('text-hidden-hide-email-expiring', { text: { text: enc('send-text-hidden'), hidden: true }, hideEmail: true, expirationDate: inDays(5) }, { type: 0, hideEmail: true, hidden: true, hasExpirationDate: true });
  await createSend('text-disabled', { disabled: true }, { type: 0, disabled: true });
  const exhausted = await createSend('text-max-access-reached', { maxAccessCount: 1 }, { type: 0, accessCount: 1, maxAccessCount: 1, accessible: false });
  assert((await accessV1(exhausted.accessId)).status === 200, 'send access (exhausting)');
  // authType 0 (email OTP) is refused with 501 by this server, so there is no such send.

  const sendFile = Buffer.from('encrypted-send-file-bytes:'.repeat(20));
  const fileSend = await api(vault, '/api/sends/file/v2', {
    method: 'POST',
    json: {
      type: 1,
      name: enc('send-name-file'),
      notes: null,
      key: enc('send-key-file'),
      file: { fileName: enc('send-file-name') },
      fileLength: sendFile.length,
      deletionDate: inDays(7),
      expirationDate: null,
      maxAccessCount: 5,
      disabled: false,
      hideEmail: false,
      password: null,
    },
  });
  {
    const uploadUrl = new URL(fileSend.url);
    const upload = await http.fetch(uploadUrl.pathname + uploadUrl.search, {
      method: 'PUT',
      headers: { 'x-ms-blob-type': 'BlockBlob', 'Content-Length': String(sendFile.length) },
      body: new Uint8Array(sendFile),
    });
    assert(upload.status === 201, `send file upload: ${upload.status}`);
    const send = fileSend.sendResponse;
    const fileAccess = await http.ok(`/api/sends/${send.accessId}/access/file/${send.file.id}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: {} });
    const download = new URL(fileAccess.url);
    const got = await http.fetch(download.pathname + download.search);
    assert(got.status === 200 && Buffer.from(await got.arrayBuffer()).equals(sendFile), 'send file download');
    sends.file = {
      id: send.id,
      accessId: send.accessId,
      fileId: send.file.id,
      objectKey: `sends/${send.id}/${send.file.id}`,
      size: sendFile.length,
      sha256: createHash('sha256').update(sendFile).digest('hex'),
      expected: { type: 1, accessCount: 1, maxAccessCount: 5 },
    };
  }
  manifest.features.sends = { owner: 'vault', sends };

  // --- equivalent domains ----------------------------------------------------

  const domainsBefore = await api(vault, '/api/settings/domains');
  const globalTypes: number[] = (domainsBefore.globalEquivalentDomains ?? domainsBefore.GlobalEquivalentDomains ?? []).map((g: any) => g.type ?? g.Type);
  const excludedTypes = globalTypes.slice(0, 2);
  const domains = await api(vault, '/api/settings/domains', {
    method: 'PUT',
    json: {
      customEquivalentDomains: [
        { domains: ['fixture.example', 'fixture-mirror.example'], excluded: false },
        { domains: ['paused.example', 'paused-mirror.example'], excluded: true },
      ],
      excludedGlobalEquivalentDomains: excludedTypes,
    },
  });
  manifest.features.equivalentDomains = {
    owner: 'vault',
    expected: {
      equivalentDomains: domains.equivalentDomains ?? domains.EquivalentDomains,
      customEquivalentDomains: domains.customEquivalentDomains ?? domains.CustomEquivalentDomains,
      excludedGlobalTypes: excludedTypes,
    },
  };

  // --- personal API key ------------------------------------------------------

  const initialApiKey = await api(vault, '/api/accounts/api-key', { method: 'POST', json: { masterPasswordHash: mph('vault') } });
  const rotatedApiKey = await api(vault, '/api/accounts/rotate-api-key', { method: 'POST', json: { masterPasswordHash: mph('vault') } });
  const retrievedApiKey = await api(vault, '/api/accounts/api-key', { method: 'POST', json: { masterPasswordHash: mph('vault') } });
  assert(initialApiKey.apiKey !== rotatedApiKey.apiKey && rotatedApiKey.apiKey === retrievedApiKey.apiKey, 'api key rotation');
  const apiLogin = await http.token({
    grant_type: 'client_credentials',
    client_id: `user.${vault.userId}`,
    client_secret: rotatedApiKey.apiKey,
    scope: 'api',
    deviceType: '21',
    deviceIdentifier: fixedUuid('vault:sdk'),
    deviceName: 'sdk',
  });
  assert(apiLogin.status === 200, `client_credentials: ${JSON.stringify(apiLogin.body)}`);
  account('vault').apiKey = { clientId: `user.${vault.userId}`, clientSecret: rotatedApiKey.apiKey, storedFormat: 'plaintext (current)' };
  recordDevice('vault', 'sdk', { type: 21, clientId: `user.${vault.userId}`, via: 'client_credentials' });

  // --- auth requests (login with device) ------------------------------------

  const authRequests: Record<string, any> = {};
  async function createAuthRequest(label: string): Promise<{ id: string; deviceIdentifier: string; accessCode: string }> {
    const deviceIdentifier = fixedUuid(`vault:auth-request:${label}`);
    const accessCode = `code${createHash('sha256').update(label).digest('hex').slice(0, 21)}`;
    const created = await http.ok('/api/auth-requests', {
      method: 'POST',
      headers: { 'X-Forwarded-For': nextIp(), 'Device-Type': '9' },
      json: {
        email: E.vault,
        publicKey: Buffer.from(`device-public-key-${label}`).toString('base64'),
        deviceIdentifier,
        accessCode,
        type: 0,
        fingerprintPhrase: 'alpha-bravo-charlie-delta-echo',
      },
    });
    authRequests[label] = { id: created.id, deviceIdentifier, accessCode };
    return authRequests[label];
  }
  const approve = (id: string, approved: boolean) =>
    api(vault, `/api/auth-requests/${id}`, {
      method: 'PUT',
      json: { key: approved ? rsaEnc(`auth-request-key-${id}`) : null, masterPasswordHash: null, deviceIdentifier: vault.deviceIdentifier, requestApproved: approved },
    });
  await createAuthRequest('pending');
  authRequests.pending.expected = { state: 'pending' };
  const approvedReq = await createAuthRequest('approved');
  await approve(approvedReq.id, true);
  authRequests.approved.expected = { state: 'approved, not yet used' };
  const deniedReq = await createAuthRequest('denied');
  await approve(deniedReq.id, false);
  authRequests.denied.expected = { state: 'denied' };
  const usedReq = await createAuthRequest('used');
  await approve(usedReq.id, true);
  const redeemed = await http.token(
    {
      grant_type: 'password',
      username: E.vault,
      password: usedReq.accessCode,
      authRequest: usedReq.id,
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceIdentifier: usedReq.deviceIdentifier,
      deviceName: 'auth-request-device',
    },
    { 'X-Forwarded-For': nextIp() },
  );
  assert(redeemed.status === 200, `auth request login: ${JSON.stringify(redeemed.body)}`);
  authRequests.used.expected = { state: 'approved and redeemed (authentication_date set)' };
  manifest.features.authRequests = { owner: 'vault', requests: authRequests, note: 'Auth requests expire 15 minutes after creation; their timestamps are left as generated.' };

  // --- organizations -------------------------------------------------------

  const org = await api(sessions.admin, '/api/organizations', {
    method: 'POST',
    json: {
      name: 'Fixture Org',
      billingEmail: E.admin,
      key: rsaEnc('org-key-admin'),
      collectionName: enc('collection-engineering'),
      keys: { publicKey: Buffer.from('fixture-org-public').toString('base64'), encryptedPrivateKey: enc('fixture-org-private') },
      planType: 0,
    },
  });
  const collections: Record<string, string> = {};
  collections.engineering = (await api(sessions.admin, `/api/organizations/${org.id}/collections`)).data[0].id;
  for (const name of ['finance', 'operations']) {
    collections[name] = (await api(sessions.admin, `/api/organizations/${org.id}/collections`, {
      method: 'POST',
      json: { name: enc(`collection-${name}`), groups: [], users: [] },
    })).id;
  }
  const members: Record<string, any> = {};
  async function invite(key: AccountKey, type: number | string, grants: Array<[string, { readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }]>, permissions?: Record<string, boolean>) {
    await api(sessions.admin, `/api/organizations/${org.id}/users/invite`, {
      method: 'POST',
      json: {
        emails: [E[key]],
        type,
        collections: grants.map(([c, g]) => ({ id: collections[c], readOnly: !!g.readOnly, hidePasswords: !!g.hidePasswords, manage: !!g.manage })),
        groups: [],
        ...(permissions ? { permissions } : {}),
      },
    });
    const invitations = await api(sessions[key], '/api/organizations/invitations');
    const memberId = invitations.data.find((m: any) => (m.organizationId ?? m.orgId ?? org.id) === org.id)?.id ?? invitations.data[0].id;
    members[key] = { memberId, invitedType: type, grants: Object.fromEntries(grants.map(([c, g]) => [c, g])) };
    return memberId;
  }
  const accept = (key: AccountKey) => api(sessions[key], `/api/organizations/${org.id}/users/${members[key].memberId}/accept`, { method: 'POST', json: {} });
  const confirm = (key: AccountKey) => api(sessions.admin, `/api/organizations/${org.id}/users/${members[key].memberId}/confirm`, { method: 'POST', json: { key: rsaEnc(`org-key-${key}`) } });

  await invite('argon', 1, []);
  await invite('vault', 2, [['engineering', {}], ['operations', { manage: true }]]);
  await invite('totp', 2, [['engineering', { readOnly: true, hidePasswords: true }], ['finance', { readOnly: true }]]);
  await invite('manager', 3, [['finance', {}]]);
  await invite('custom', 4, [], { editAnyCollection: true, deleteAnyCollection: true, createNewCollections: true });
  await invite('yubikey', 2, [['engineering', {}]]);
  await invite('webauthn2fa', 2, [['finance', { hidePasswords: true }]]);
  await invite('passkey', 2, [['operations', {}]]);
  for (const key of ['argon', 'vault', 'totp', 'manager', 'custom', 'webauthn2fa', 'passkey'] as const) await accept(key);
  for (const key of ['argon', 'vault', 'totp', 'manager', 'custom', 'passkey'] as const) await confirm(key);
  await api(sessions.admin, `/api/organizations/${org.id}/users/${members.passkey.memberId}/revoke`, { method: 'PUT' });
  Object.assign(members.argon, { expected: { type: 1, status: 2, accessAll: true } });
  Object.assign(members.vault, { expected: { type: 2, status: 2 } });
  Object.assign(members.totp, { expected: { type: 2, status: 2 } });
  Object.assign(members.manager, { expected: { type: 3, status: 2, accessAll: false, note: 'legacy Manager role, exposed to clients as Custom (4)' } });
  Object.assign(members.custom, { expected: { type: 3, status: 2, accessAll: true, note: 'invited as Custom (4) with all collection permissions; stored as Manager + access_all' } });
  Object.assign(members.yubikey, { expected: { type: 2, status: 0 } });
  Object.assign(members.webauthn2fa, { expected: { type: 2, status: 1 } });
  Object.assign(members.passkey, { expected: { type: 2, status: -1, revokedStatus: 2 } });

  const orgCiphers: Record<string, string> = {};
  async function orgCipher(label: string, collectionNames: string[], payload: Record<string, unknown>): Promise<string> {
    const created = await api(sessions.admin, '/api/ciphers/create', {
      method: 'POST',
      json: {
        cipher: { name: enc(`org-name-${label}`), notes: null, reprompt: 0, organizationId: org.id, ...payload },
        collectionIds: collectionNames.map((c) => collections[c]),
      },
    });
    orgCiphers[label] = created.id;
    return created.id;
  }
  await orgCipher('login-engineering', ['engineering'], { type: 1, login: { username: enc('org-user'), password: enc('org-pass'), uris: [{ uri: enc('org-uri'), match: null }] } });
  await orgCipher('login-shared', ['engineering', 'finance'], { type: 1, key: enc('org-cipher-key'), login: { username: enc('shared-user'), password: enc('shared-pass') } });
  await orgCipher('note-finance-operations', ['finance', 'operations'], { type: 2, secureNote: { type: 0 } });
  await orgCipher('card-operations', ['operations'], { type: 3, card: { cardholderName: enc('org-holder'), number: enc('org-number') } });
  await orgCipher('deleted', ['engineering'], { type: 1, login: { username: enc('deleted-user') } });
  await http.ok(`/api/ciphers/${orgCiphers.deleted}/delete`, { method: 'PUT', token: sessions.admin.accessToken });
  await attach(sessions.admin, orgCiphers['card-operations'], 'org-card', Buffer.from('encrypted-attachment-bytes:org-card'));
  // A personal item moved into the organization.
  const toShare = await api(sessions.admin, '/api/ciphers', { method: 'POST', json: { ...cipherBase('admin-shared'), type: 1, login: { username: enc('admin-user') } } });
  await api(sessions.admin, `/api/ciphers/${toShare.id}/share`, {
    method: 'PUT',
    json: { cipher: { ...cipherBase('admin-shared'), type: 1, login: { username: enc('admin-user') }, organizationId: org.id }, collectionIds: [collections.operations] },
  });
  orgCiphers['shared-from-personal'] = toShare.id;
  // Admin keeps one personal item.
  ciphers['admin-personal'] = (await api(sessions.admin, '/api/ciphers', { method: 'POST', json: { ...cipherBase('admin-personal'), type: 2, secureNote: { type: 0 } } })).id;

  // Per-user state on org items (cipher_user_state).
  const totpFolder = (await api(sessions.totp, '/api/folders', { method: 'POST', json: { name: enc('folder-totp-org-items') } })).id;
  await api(sessions.totp, `/api/ciphers/${orgCiphers['login-engineering']}/partial`, { method: 'PUT', json: { folderId: totpFolder, favorite: true } });
  await api(sessions.vault, `/api/ciphers/${orgCiphers['card-operations']}/archive`, { method: 'PUT' });

  // A second organization, owned by the Argon2 user.
  const org2 = await api(sessions.argon, '/api/organizations', {
    method: 'POST',
    json: { name: 'Argon Org', billingEmail: E.argon, key: rsaEnc('org2-key-argon'), collectionName: enc('collection-argon-default'), planType: 0 },
  });
  const org2Collection = (await api(sessions.argon, `/api/organizations/${org2.id}/collections`)).data[0].id;
  const org2Cipher = (await api(sessions.argon, '/api/ciphers/create', {
    method: 'POST',
    json: { cipher: { type: 1, name: enc('org2-login'), reprompt: 0, organizationId: org2.id, login: { username: enc('org2-user') } }, collectionIds: [org2Collection] },
  })).id;

  manifest.organizations = {
    fixture: { id: org.id, name: 'Fixture Org', owner: 'admin', collections, members, ciphers: orgCiphers },
    argon: { id: org2.id, name: 'Argon Org', owner: 'argon', collections: { default: org2Collection }, ciphers: { login: org2Cipher }, note: 'created without an org key pair' },
  };
  manifest.features.ciphers = { owner: 'vault', folders, ciphers, notes: {
    login: 'type 1, favorite, folder, uris (match 0/3/null, uriChecksum), fido2Credentials, totp, fields (text/hidden/boolean/linked), passwordHistory, passwordRevisionDate; 2 attachments',
    note: 'type 2 in folder "work"; 1 attachment',
    card: 'type 3, reprompt 1',
    identity: 'type 4, cipher-level key',
    'ssh-key': 'type 5, archived',
    'bank-account': 'type 6, soft-deleted (trash)',
    'drivers-license': 'type 7',
    passport: 'type 8',
    'key-added': 'type 1 updated with a new cipher key: ciphers.data carries keyAddedFromRevision',
    'admin-personal': 'owned by admin',
  } };
  manifest.features.attachments = attachments;
  manifest.features.perUserOrgState = {
    totpFavoriteAndFolder: { user: 'totp', cipher: orgCiphers['login-engineering'], folderId: totpFolder, favorite: true },
    vaultArchived: { user: 'vault', cipher: orgCiphers['card-operations'], archived: true },
  };

  // --- two-factor ------------------------------------------------------------

  // TOTP through the web vault route with a fixed secret.
  const totpCodes = new TotpCodes();
  const totpEnabled = await api(sessions.totp, '/api/accounts/totp', {
    method: 'PUT',
    json: { enabled: true, secret: TOTP_SECRET, token: (await totpCodes.next(TOTP_SECRET)).code, masterPasswordHash: mph('totp') },
  });
  const recovery = await api(sessions.totp, '/api/two-factor/get-recover', { method: 'POST', json: { masterPasswordHash: mph('totp') } });
  assert(recovery.code === totpEnabled.recoveryCode || recovery.Code === totpEnabled.recoveryCode, 'recovery code stable');
  const totpLogin = await login('totp', { device: 'remembered', extra: { twoFactorProvider: '0', twoFactorToken: (await totpCodes.next(TOTP_SECRET)).code, twoFactorRemember: '1' } });
  assert(typeof totpLogin.body.TwoFactorToken === 'string', 'TOTP remember token');
  sessions.totp = totpLogin.session;
  Object.assign(account('totp'), {
    covers: ['TOTP (provider 0) with fixed secret', 'recovery code', 'trusted remember-me device token (provider 5)', 'org user: read-only + hide-passwords collection grant', 'per-user folder/favorite on an org item'],
    twoFactor: { providers: [0], totpSecret: TOTP_SECRET, recoveryCode: totpEnabled.recoveryCode },
    rememberToken: { deviceIdentifier: totpLogin.session.deviceIdentifier, token: totpLogin.body.TwoFactorToken },
  });
  recordDevice('totp', 'remembered', { type: 25, clientId: 'cli', rememberToken: totpLogin.body.TwoFactorToken });

  // YubiKey OTP (admin configured the Yubico API credentials above).
  await api(sessions.yubikey, '/api/two-factor/yubikey', {
    method: 'PUT',
    json: { key1: yubiKeyOtp(YUBIKEY_PUBLIC_ID), key2: '', key3: '', key4: '', key5: '', nfc: true, masterPasswordHash: mph('yubikey') },
  });
  const yubiLogin = await login('yubikey', { device: 'otp', extra: { twoFactorProvider: '3', twoFactorToken: yubiKeyOtp(YUBIKEY_PUBLIC_ID) } });
  sessions.yubikey = yubiLogin.session;
  Object.assign(account('yubikey'), {
    covers: ['YubiKey OTP (provider 3), NFC on', 'org member in state invited (0)'],
    twoFactor: { providers: [3], yubikeyPublicId: YUBIKEY_PUBLIC_ID, nfc: true },
  });

  // WebAuthn as a second factor (provider 7).
  const exportCredential = (credential: SoftCredential) => ({
    credentialId: credential.id,
    rpId: credential.rpId,
    userHandle: b64url(credential.userHandle),
    privateKeyPkcs8: (credential.privateKey as KeyObject).export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    privateKeyJwk: (credential.privateKey as KeyObject).export({ format: 'jwk' }),
    prfSeed: credential.prfSeed.toString('base64'),
    counter: credential.counter,
  });
  const twoFactorAuthenticator = new SoftAuthenticator();
  const challenge = await api(sessions.webauthn2fa, '/api/two-factor/get-webauthn-challenge', { method: 'POST', json: { masterPasswordHash: mph('webauthn2fa') } });
  const { credential: securityKey, response: securityKeyResponse } = twoFactorAuthenticator.create(challenge, { origin });
  await api(sessions.webauthn2fa, '/api/two-factor/webauthn', {
    method: 'PUT',
    json: { id: 1, name: 'Fixture security key', masterPasswordHash: mph('webauthn2fa'), deviceResponse: securityKeyResponse },
  });
  const deviceFor2fa = fixedUuid('webauthn2fa:remembered');
  const wChallenge = await http.token(passwordGrantFields(E.webauthn2fa, { masterPasswordHash: mph('webauthn2fa'), deviceIdentifier: deviceFor2fa }));
  assert(wChallenge.status === 400 && wChallenge.body.TwoFactorProviders2?.['7'], 'webauthn 2fa challenge');
  const assertion = twoFactorAuthenticator.get(wChallenge.body.TwoFactorProviders2['7'], { origin, style: 'bitwarden' }, securityKey);
  const w2fa = await login('webauthn2fa', { device: 'remembered', extra: { twoFactorProvider: '7', twoFactorToken: JSON.stringify(assertion), twoFactorRemember: '1' } });
  assert(typeof w2fa.body.TwoFactorToken === 'string', 'webauthn remember token');
  sessions.webauthn2fa = w2fa.session;
  Object.assign(account('webauthn2fa'), {
    covers: ['WebAuthn security key as 2FA (provider 7)', 'trusted remember-me device token', 'org member in state accepted (1)'],
    twoFactor: { providers: [7], webauthnKeys: [{ name: 'Fixture security key', ...exportCredential(securityKey) }] },
    rememberToken: { deviceIdentifier: w2fa.session.deviceIdentifier, token: w2fa.body.TwoFactorToken },
  });

  // --- account passkeys ------------------------------------------------------

  const passkeyAuthenticator = new SoftAuthenticator();
  const passkeys: any[] = [];
  async function registerPasskey(label: string, body: Record<string, unknown>, style: 'w3c' | 'bitwarden', stripPrf: boolean): Promise<SoftCredential> {
    const { options, token } = await api(sessions.passkey, '/api/webauthn/attestation-options', { method: 'POST', json: { masterPasswordHash: mph('passkey') } });
    const authenticator = new SoftAuthenticator();
    const opts = stripPrf ? { ...options, extensions: {} } : options;
    const { credential, response } = authenticator.create(opts, { origin, style });
    const saved = await api(sessions.passkey, '/api/webauthn', { method: 'POST', json: { token, deviceResponse: response, ...body } });
    passkeyAuthenticator.credentials.push(credential);
    passkeys.push({ label, id: saved.id, name: saved.name, prfStatus: saved.prfStatus, ...exportCredential(credential), keySet: body.encryptedUserKey ? { encryptedUserKey: body.encryptedUserKey, encryptedPublicKey: body.encryptedPublicKey, encryptedPrivateKey: body.encryptedPrivateKey } : null });
    return credential;
  }
  const prfCredential = await registerPasskey('prf-with-key-set', {
    name: 'Laptop passkey',
    supportsPrf: true,
    encryptedUserKey: rsaEnc('prf-user-key'),
    encryptedPublicKey: enc('prf-public-key'),
    encryptedPrivateKey: enc('prf-private-key'),
  }, 'w3c', false);
  await registerPasskey('prf-supported-no-key-set', { name: 'Phone passkey', supportsPrf: true }, 'bitwarden', false);
  await registerPasskey('no-prf', {}, 'w3c', true);
  // Login with the PRF passkey (proves the stored credential works and bumps its counter).
  const assertionOptions = await http.ok('/identity/accounts/webauthn/assertion-options');
  const passkeyAssertion = passkeyAuthenticator.get(assertionOptions.options, { origin, userHandle: true }, prfCredential);
  const passkeyLogin = await http.token({
    grant_type: 'webauthn',
    token: assertionOptions.token,
    deviceResponse: JSON.stringify(passkeyAssertion),
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceIdentifier: fixedUuid('passkey:webauthn-login'),
    deviceName: 'passkey-login',
  });
  assert(passkeyLogin.status === 200 && passkeyLogin.body.UserDecryptionOptions?.WebAuthnPrfOption, `passkey login: ${JSON.stringify(passkeyLogin.body)}`);
  passkeys[0].counter = prfCredential.counter;
  Object.assign(account('passkey'), {
    covers: ['3 account passkeys: PRF with key set (prfStatus 0), PRF supported without key set (1), no PRF (2)', 'org member confirmed then revoked (-1)'],
    passkeys,
    expectedUserHandle: b64url(dotNetGuidBytes(sessions.passkey.userId)),
  });

  // --- remaining accounts ------------------------------------------------------

  Object.assign(account('manager'), { covers: ['org member with legacy Manager role (type 3, no access_all)'] });
  Object.assign(account('custom'), { covers: ['org member invited as Custom with all collection permissions (stored type 3 + access_all)'] });

  // --- backup settings (encrypted envelope with credentials) ------------------

  const backupSettings = await api(sessions.admin, '/api/admin/backup/settings', {
    method: 'PUT',
    json: {
      masterPasswordHash: mph('admin'),
      destinations: [
        {
          id: 'fixture-s3-destination',
          name: 'Fixture S3',
          type: 's3',
          includeAttachments: true,
          destination: {
            endpoint: 'https://s3.backup.fixture.example',
            bucket: 'fixture-backups',
            addressingStyle: 'virtual-hosted-style',
            region: 'eu-central-1',
            accessKeyId: 'FIXTUREACCESSKEY',
            secretAccessKey: 'fixture-s3-secret-access-key',
            rootPath: 'moliwarden/prod',
          },
          schedule: { enabled: true, intervalHours: 12, startTime: '02:30', timezone: 'Europe/Berlin', retentionCount: 14 },
        },
        {
          id: 'fixture-webdav-destination',
          name: 'Fixture WebDAV',
          type: 'webdav',
          includeAttachments: false,
          destination: {
            baseUrl: 'https://dav.backup.fixture.example/remote.php/dav/files/fixture',
            username: 'fixture-dav-user',
            password: 'fixture-dav-password',
            remotePath: 'backups/moliwarden',
          },
          schedule: { enabled: false, intervalHours: 24, startTime: '03:00', timezone: 'UTC', retentionCount: null },
        },
      ],
    },
  });
  assert(backupSettings.destinations.length === 2, 'backup settings saved');
  manifest.features.backupSettings = {
    configKey: 'backup.settings.v1',
    storedFormat: 'envelope v2: runtime AES-GCM (key from JWT_SECRET) + portable AES-GCM with the DEK RSA-OAEP(SHA-1)-wrapped for each active admin with a valid SPKI public key',
    expected: {
      destinations: [
        { id: 'fixture-s3-destination', type: 's3', secretAccessKey: 'fixture-s3-secret-access-key', accessKeyId: 'FIXTUREACCESSKEY', schedule: { enabled: true, intervalHours: 12, startTime: '02:30', timezone: 'Europe/Berlin', retentionCount: 14 } },
        { id: 'fixture-webdav-destination', type: 'webdav', password: 'fixture-dav-password', username: 'fixture-dav-user', schedule: { enabled: false, intervalHours: 24, startTime: '03:00', timezone: 'UTC', retentionCount: null } },
      ],
      portableWrapUserIds: [sessions.admin.userId],
    },
  };

  // --- ban -------------------------------------------------------------------

  await api(sessions.admin, `/api/admin/users/${sessions.banned.userId}/status`, { method: 'PUT', json: { status: 'banned', masterPasswordHash: mph('admin') } });
  Object.assign(account('banned'), { status: 'banned', covers: ['banned by the admin: login must be refused'] });

  // --- legacy stored formats (direct SQL) -------------------------------------

  await applyLegacyVariants(http, sessions);

  // --- expectations from the live server ---------------------------------------

  for (const key of Object.keys(E) as AccountKey[]) {
    if (key === 'banned') continue;
    const sync = await api(sessions[key], '/api/sync');
    const ciphersInSync: any[] = sync.ciphers ?? [];
    manifest.expectations[key] = {
      sync: {
        ciphers: ciphersInSync.length,
        deletedCiphers: ciphersInSync.filter((c) => c.deletedDate).length,
        archivedCiphers: ciphersInSync.filter((c) => c.archivedDate).length,
        orgCiphers: ciphersInSync.filter((c) => c.organizationId).length,
        folders: (sync.folders ?? []).length,
        collections: (sync.collections ?? []).length,
        sends: (sync.sends ?? []).length,
        organizations: (sync.profile?.organizations ?? []).length,
        attachments: ciphersInSync.reduce((n, c) => n + (c.attachments?.length ?? 0), 0),
      },
      cipherIds: ciphersInSync.map((c) => c.id).sort(),
    };
  }

  // --- admin backup export (with attachments) --------------------------------

  const exported = await http.fetch('/api/admin/backup/export', {
    method: 'POST',
    token: sessions.admin.accessToken,
    json: { includeAttachments: true, masterPasswordHash: mph('admin') },
  });
  assert(exported.status === 200, `backup export: ${exported.status} ${await exported.clone().text()}`);
  // The server archive lists the attachment blobs; the web vault downloads
  // each one and rebuilds the zip (webapp/src/lib/api/backup.ts
  // buildCompleteAdminBackupExport). Do the same so the archive is complete.
  const serverFileName = /filename="?([^";]+)"?/.exec(exported.headers.get('Content-Disposition') ?? '')?.[1] ?? 'nodewarden_backup.zip';
  const zipped = unzipSync(new Uint8Array(await exported.arrayBuffer()));
  const archiveManifest = JSON.parse(Buffer.from(zipped['manifest.json']).toString('utf8'));
  for (const blob of archiveManifest.attachmentBlobs ?? []) {
    const res = await http.fetch('/api/admin/backup/blob', {
      method: 'POST',
      token: sessions.admin.accessToken,
      json: { blobName: blob.blobName, masterPasswordHash: mph('admin') },
    });
    assert(res.status === 200, `backup blob ${blob.blobName}: ${res.status}`);
    zipped[`attachments/${blob.cipherId}/${blob.attachmentId}.bin`] = new Uint8Array(await res.arrayBuffer());
  }
  backupZip = Buffer.from(zipSync(zipped, { level: 0, mtime: new Date('2026-01-01T00:00:00Z') }));
  const checksumPrefix = createHash('sha256').update(backupZip).digest('hex').slice(0, 5);
  manifest.features.backupExport = {
    file: 'v1-backup.zip',
    serverFileName,
    webVaultFileName: serverFileName.replace(/(_[0-9a-f]{5})?\.zip$/i, `_${checksumPrefix}.zip`),
    entries: Object.keys(zipped).sort(),
    tableCounts: archiveManifest.tableCounts,
    note: 'Built like the web vault export: server zip + attachments/<cipherId>/<attachmentId>.bin fetched via /api/admin/backup/blob, re-zipped with level 0. Sends, devices, refresh tokens, invites, audit logs and auth requests are not part of backup archives.',
  };
}

let backupZip: Buffer | null = null;

// ---------------------------------------------------------------------------
// Legacy stored formats: things the current code still READS but no longer
// WRITES. Each gets its own clearly labelled user (and row), is checked against
// the running server after the mutation, and is listed in manifest.legacyVariants.
// File references point at the v1 server code (FIXTURE_SERVER_COMMIT).

const LEGACY_TOTP_SECRET_STORED = 'jbsw y3dp-ehpk 3pxp-moli ward-enle gacy==';
const LEGACY_TOTP_SECRET = 'JBSWY3DPEHPK3PXPMOLIWARDENLEGACY';
const LEGACY_RECOVERY_CODE_STORED = 'abcdefghijklmnopqrstuvwxyz234567';
const LEGACY_YUBIKEY_PUBLIC_ID = 'cccccbhjklnv';
const LEGACY_YUBIKEY_STORED = '  CCCCCBHJKLNV ';
const LEGACY_REFRESH_TOKEN = 'legacy-fixture-unbound-refresh-token-0001';

async function applyLegacyVariants(http: Http, sessions: Record<AccountKey, Session>): Promise<void> {
  const mph = (key: AccountKey) => masterPasswordHash(E[key]);
  const variants = manifest.legacyVariants as any[];
  const variant = (key: AccountKey, entry: Record<string, unknown>) => {
    variants.push({ account: key, ...entry });
    const acc = account(key);
    acc.covers = [...(acc.covers ?? []), `legacy variant ${entry.id}`];
  };
  const sha256Hex = (value: string) => createHash('sha256').update(value).digest('hex');

  // Ciphers for the legacy cipher-row account, created normally first.
  const lc = sessions.legacyCipher;
  const lcFolder = (await http.ok('/api/folders', { method: 'POST', token: lc.accessToken, json: { name: enc('legacy-cipher-folder') } })).id;
  const allInData = (await http.ok('/api/ciphers', {
    method: 'POST',
    token: lc.accessToken,
    json: { type: 1, name: enc('legacy-all-in-data'), notes: enc('legacy-all-in-data-notes'), key: enc('legacy-all-in-data-key'), reprompt: 1, favorite: false, folderId: lcFolder, login: { username: enc('legacy-user') } },
  })).id;
  const pascalKeys = (await http.ok('/api/ciphers', {
    method: 'POST',
    token: lc.accessToken,
    json: { type: 2, name: enc('legacy-pascal-keys'), notes: null, reprompt: 0, favorite: false, folderId: null, secureNote: { type: 0 } },
  })).id;
  const sshAlias = (await http.ok('/api/ciphers', {
    method: 'POST',
    token: lc.accessToken,
    json: { type: 5, name: enc('legacy-ssh-alias'), notes: null, reprompt: 0, favorite: false, folderId: null, sshKey: { privateKey: enc('legacy-ssh-private'), publicKey: enc('legacy-ssh-public'), keyFingerprint: enc('legacy-ssh-fingerprint') } },
  })).id;

  await withDb(FIXTURE_DATABASE_URL, async (db) => {
    const userId = (key: AccountKey) => sessions[key].userId;

    // 1. Raw client hash as master_password_hash.
    await db.query('UPDATE users SET master_password_hash = $1 WHERE id = $2', [mph('legacyRawHash'), userId('legacyRawHash')]);
    variant('legacyRawHash', {
      id: 'users.master_password_hash:raw-client-hash',
      table: 'users',
      column: 'master_password_hash',
      stored: 'the base64 client master password hash itself, without the "$s$" server-hash prefix',
      currentWrite: '"$s$" + base64(PBKDF2-SHA256(client hash, email)) (src/services/auth.ts hashPasswordServer)',
      readBy: 'src/services/auth.ts:160-167 verifyPassword (constant-time compare when the prefix is missing; never re-hashed)',
      expected: 'password login with the manifest masterPasswordHash succeeds',
    });

    // 2. One-way hashed personal API key.
    const hashed = `sha256:${sha256Hex(LEGACY_API_KEY_SECRET)}`;
    await db.query('UPDATE users SET api_key = $1 WHERE id = $2', [hashed, userId('legacyApiKey')]);
    account('legacyApiKey').apiKey = { clientId: `user.${userId('legacyApiKey')}`, clientSecret: LEGACY_API_KEY_SECRET, storedFormat: 'sha256:<hex> (legacy)' };
    variant('legacyApiKey', {
      id: 'users.api_key:sha256-hash',
      table: 'users',
      column: 'api_key',
      stored: hashed,
      currentWrite: 'plaintext 30-char alphanumeric secret',
      readBy: 'src/utils/api-key.ts:30-42 verifyApiKey; src/handlers/accounts.ts:1603-1610 answers 409 to POST /api/accounts/api-key until rotated',
      expected: 'client_credentials with the manifest clientSecret succeeds; POST /api/accounts/api-key answers 409',
    });

    // 3. Domain rules only in the old equivalent_domains column.
    await db.query(
      "INSERT INTO domain_settings(user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at) VALUES($1, $2, '[]', '[]', $3) " +
        'ON CONFLICT(user_id) DO UPDATE SET equivalent_domains = excluded.equivalent_domains, custom_equivalent_domains = excluded.custom_equivalent_domains, excluded_global_equivalent_domains = excluded.excluded_global_equivalent_domains',
      [userId('legacyDomains'), JSON.stringify([['legacy.example', 'legacy-mirror.example']]), '2025-06-01T00:00:00.000Z'],
    );
    variant('legacyDomains', {
      id: 'domain_settings:equivalent_domains-only',
      table: 'domain_settings',
      column: 'equivalent_domains / custom_equivalent_domains',
      stored: 'equivalent_domains=[["legacy.example","legacy-mirror.example"]], custom_equivalent_domains=[]',
      currentWrite: 'custom_equivalent_domains holds the rules; equivalent_domains the derived active groups',
      readBy: 'src/services/storage-domain-rules-repo.ts:30-37 getUserDomainSettings (derives custom rules from equivalent_domains)',
      expected: 'GET /api/settings/domains lists one active custom rule [legacy.example, legacy-mirror.example]',
    });

    // 4. TOTP secret and recovery code in un-normalized form.
    await db.query('UPDATE users SET totp_secret = $1, totp_recovery_code = $2 WHERE id = $3', [LEGACY_TOTP_SECRET_STORED, LEGACY_RECOVERY_CODE_STORED, userId('legacyTotp')]);
    Object.assign(account('legacyTotp'), { twoFactor: { providers: [0], totpSecret: LEGACY_TOTP_SECRET, totpSecretStored: LEGACY_TOTP_SECRET_STORED, recoveryCode: LEGACY_RECOVERY_CODE_STORED.toUpperCase().replace(/(.{4})/g, '$1 ').trim() } });
    variant('legacyTotp', {
      id: 'users.totp_secret+totp_recovery_code:unnormalized',
      table: 'users',
      column: 'totp_secret, totp_recovery_code',
      stored: `totp_secret=${JSON.stringify(LEGACY_TOTP_SECRET_STORED)}, totp_recovery_code=${JSON.stringify(LEGACY_RECOVERY_CODE_STORED)}`,
      currentWrite: 'upper-case base32 without separators/padding; recovery code as 8 upper-case groups of 4',
      readBy: 'src/utils/totp.ts:5-16 normalizeBase32; src/utils/recovery-code.ts:5-7,26 recoveryCodeEquals',
      expected: 'TOTP codes for the normalized secret log in; the recovery code (any grouping/case) is accepted as provider 8',
    });

    // 5. YubiKey public id in upper case with padding.
    await db.query('UPDATE users SET yubikey_key1 = $1, yubikey_nfc = 0 WHERE id = $2', [LEGACY_YUBIKEY_STORED, userId('legacyYubikey')]);
    Object.assign(account('legacyYubikey'), { twoFactor: { providers: [3], yubikeyPublicId: LEGACY_YUBIKEY_PUBLIC_ID, yubikeyStored: LEGACY_YUBIKEY_STORED, nfc: false } });
    variant('legacyYubikey', {
      id: 'users.yubikey_key1:unnormalized-public-id',
      table: 'users',
      column: 'yubikey_key1',
      stored: JSON.stringify(LEGACY_YUBIKEY_STORED),
      currentWrite: 'lower-case 12-char modhex public id',
      readBy: 'src/utils/yubico-otp.ts:37-49 userYubiKeyPublicIds (trim + lower-case)',
      expected: `login challenge offers provider 3; an OTP from ${LEGACY_YUBIKEY_PUBLIC_ID} is accepted`,
    });

    // 6. PBKDF2 below today's registration minimum.
    await db.query('UPDATE users SET kdf_iterations = 5000 WHERE id = $1', [userId('legacyKdf')]);
    account('legacyKdf').kdf = { type: 0, iterations: 5000, memory: null, parallelism: null };
    variant('legacyKdf', {
      id: 'users.kdf_iterations:below-minimum',
      table: 'users',
      column: 'kdf_iterations',
      stored: '5000 (PBKDF2)',
      currentWrite: 'registration requires >= 100000; /api/accounts/kdf is not supported',
      readBy: 'src/handlers/identity.ts:1067-1093 prelogin (echoes stored values)',
      expected: 'prelogin answers kdf 0 / kdfIterations 5000; login works',
    });

    // 7. Unknown status/role strings.
    await db.query("UPDATE users SET status = 'disabled', role = 'member' WHERE id = $1", [userId('legacyStatus')]);
    variant('legacyStatus', {
      id: 'users.status+role:non-canonical',
      table: 'users',
      column: 'status, role',
      stored: "status='disabled', role='member'",
      currentWrite: "status 'active'|'banned', role 'admin'|'user'",
      readBy: "src/services/storage-user-repo.ts:24-25 (anything but 'banned' is active, anything but 'admin' is user)",
      expected: 'login succeeds; the admin user list shows the user as an active non-admin',
    });

    // 8. Refresh token row from before stamps/client type/absolute expiry were stored.
    await db.query(
      'INSERT INTO refresh_tokens(token, user_id, expires_at, device_identifier, device_session_stamp, security_stamp, created_at, last_used_at, absolute_expires_at, client_type) VALUES($1, $2, $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL)',
      [`sha256:${sha256Hex(LEGACY_REFRESH_TOKEN)}`, userId('legacySession'), FAR_FUTURE_MS],
    );
    account('legacySession').legacyRefreshToken = LEGACY_REFRESH_TOKEN;
    variant('legacySession', {
      id: 'refresh_tokens:unbound-null-columns',
      table: 'refresh_tokens',
      column: 'device_identifier, device_session_stamp, security_stamp, created_at, last_used_at, absolute_expires_at, client_type',
      stored: 'all NULL (token key is sha256:<hex> of the manifest legacyRefreshToken, expires_at 2099-01-01)',
      currentWrite: 'every column set at issue time',
      readBy: 'src/services/storage-refresh-token-repo.ts:74-88 getRefreshTokenRecord; src/services/auth.ts:270-298 (binds stamps on first use, absolute expiry defaults to now + max)',
      expected: 'grant_type=refresh_token with the manifest legacyRefreshToken succeeds (and binds the stamps on first use)',
    });

    // 9. Cipher rows in older shapes.
    const setData = async (id: string, mutate: (data: any) => void, columns = '') => {
      const row = (await db.query('SELECT data FROM ciphers WHERE id = $1', [id])).rows[0];
      const data = JSON.parse(row.data);
      mutate(data);
      await db.query(`UPDATE ciphers SET data = $1${columns} WHERE id = $2`, [JSON.stringify(data), id]);
    };
    const scalars = (await db.query('SELECT name, notes, key, reprompt, folder_id FROM ciphers WHERE id = $1', [allInData])).rows[0];
    await setData(allInData, (data) => {
      data.name = scalars.name;
      data.notes = scalars.notes;
      data.key = scalars.key;
      data.reprompt = Number(scalars.reprompt);
      data.folderId = scalars.folder_id;
    }, ', name = NULL, notes = NULL, key = NULL, reprompt = NULL, folder_id = NULL');
    await setData(pascalKeys, (data) => {
      Object.assign(data, { Id: 'ffffffff-ffff-4fff-8fff-ffffffffffff', Edit: false, ViewPassword: false, OrganizationUseTotp: false, RevisionDate: '2020-01-01T00:00:00.000Z', Object: 'cipher' });
    });
    await setData(sshAlias, (data) => {
      data.sshKey.fingerprint = data.sshKey.keyFingerprint;
      delete data.sshKey.keyFingerprint;
    });
    account('legacyCipher').legacyCiphers = { allInData, pascalKeys, sshAlias, folderId: lcFolder };
    variant('legacyCipher', {
      id: 'ciphers:scalars-only-in-data',
      table: 'ciphers',
      row: allInData,
      stored: 'name/notes/key/reprompt/folder_id columns NULL; the values live in the data JSON (name, notes, key, reprompt, folderId)',
      currentWrite: 'scalar columns filled and stripped from data (src/services/storage-cipher-repo.ts:97-109 buildCipherData)',
      readBy: 'src/services/storage-cipher-repo.ts:111-133 parseCipherRow (column ?? data fallback)',
      expected: 'sync returns the cipher with its name, notes, key, reprompt 1 and folderId',
    });
    variant('legacyCipher', {
      id: 'ciphers:pascal-case-server-keys-in-data',
      table: 'ciphers',
      row: pascalKeys,
      stored: 'data JSON carries client copies of server-owned keys: Id, Edit, ViewPassword, OrganizationUseTotp, RevisionDate, Object',
      currentWrite: 'server-owned keys stripped case-insensitively',
      readBy: 'src/handlers/ciphers.ts:823-829 cipherToResponse (drops them from responses)',
      expected: 'sync returns the cipher with its real id and no PascalCase Id/Edit/ViewPassword/OrganizationUseTotp/RevisionDate keys',
    });
    variant('legacyCipher', {
      id: 'ciphers:ssh-key-fingerprint-alias-only',
      table: 'ciphers',
      row: sshAlias,
      stored: 'data.sshKey has "fingerprint" but no "keyFingerprint"',
      currentWrite: 'both keyFingerprint and fingerprint',
      readBy: 'src/handlers/ciphers.ts:534-560 normalizeCipherSshKeyForCompatibility',
      expected: 'sync returns sshKey.keyFingerprint equal to the stored fingerprint',
    });
  });

  // The server caches users for a few seconds; let the SQL edits show through.
  await sleep(16000);

  // Check each variant against the running server.
  const loginAs = async (key: AccountKey, device: string, extra?: Record<string, string>) =>
    http.token(passwordGrantFields(E[key], { masterPasswordHash: mph(key), deviceIdentifier: fixedUuid(`${key}:${device}`), extra }), { 'X-Forwarded-For': nextIp() });

  const raw = await loginAs('legacyRawHash', 'check');
  assert(raw.status === 200, `raw-hash login: ${JSON.stringify(raw.body)}`);

  const apiLogin = await http.token({
    grant_type: 'client_credentials',
    client_id: `user.${sessions.legacyApiKey.userId}`,
    client_secret: LEGACY_API_KEY_SECRET,
    scope: 'api',
    deviceType: '21',
    deviceIdentifier: fixedUuid('legacyApiKey:sdk'),
    deviceName: 'sdk',
  });
  assert(apiLogin.status === 200, `legacy api key login: ${JSON.stringify(apiLogin.body)}`);
  const view = await http.call('/api/accounts/api-key', { method: 'POST', token: sessions.legacyApiKey.accessToken, json: { masterPasswordHash: mph('legacyApiKey') } });
  assert(view.status === 409, `legacy api key view: ${view.status}`);

  const legacyDomains = await http.ok('/api/settings/domains', { token: sessions.legacyDomains.accessToken });
  assert(JSON.stringify(legacyDomains).includes('legacy-mirror.example'), `legacy domains: ${JSON.stringify(legacyDomains)}`);

  const totpChallenge = await loginAs('legacyTotp', 'check');
  assert(totpChallenge.status === 400 && totpChallenge.body.TwoFactorProviders2?.['0'] !== undefined, `legacy totp challenge: ${JSON.stringify(totpChallenge.body)}`);
  const totpOk = await loginAs('legacyTotp', 'check', { twoFactorProvider: '0', twoFactorToken: (await new TotpCodes().next(LEGACY_TOTP_SECRET)).code });
  assert(totpOk.status === 200, `legacy totp login: ${JSON.stringify(totpOk.body)}`);
  sessions.legacyTotp = { ...sessions.legacyTotp, accessToken: totpOk.body.access_token };

  const yubiOk = await loginAs('legacyYubikey', 'check', { twoFactorProvider: '3', twoFactorToken: yubiKeyOtp(LEGACY_YUBIKEY_PUBLIC_ID) });
  assert(yubiOk.status === 200, `legacy yubikey login: ${JSON.stringify(yubiOk.body)}`);
  sessions.legacyYubikey = { ...sessions.legacyYubikey, accessToken: yubiOk.body.access_token };

  const prelogin = await http.ok('/identity/accounts/prelogin', { method: 'POST', json: { email: E.legacyKdf } });
  assert((prelogin.kdfIterations ?? prelogin.KdfIterations) === 5000, `legacy kdf prelogin: ${JSON.stringify(prelogin)}`);
  assert((await loginAs('legacyKdf', 'check')).status === 200, 'legacy kdf login');

  assert((await loginAs('legacyStatus', 'check')).status === 200, 'legacy status login');

  // Probe the refresh-token variant with a throwaway copy so the fixture row stays unbound.
  const probe = 'legacy-fixture-probe-refresh-token';
  await withDb(FIXTURE_DATABASE_URL, (db) => db.query(
    'INSERT INTO refresh_tokens(token, user_id, expires_at) VALUES($1, $2, $3)',
    [`sha256:${sha256Hex(probe)}`, sessions.legacySession.userId, FAR_FUTURE_MS],
  ));
  const refreshed = await http.token({ grant_type: 'refresh_token', refresh_token: probe, client_id: 'cli' }, { 'X-Forwarded-For': nextIp() });
  assert(refreshed.status === 200, `legacy refresh token: ${JSON.stringify(refreshed.body)}`);
  await withDb(FIXTURE_DATABASE_URL, (db) => db.query('DELETE FROM refresh_tokens WHERE user_id = $1 AND token <> $2', [sessions.legacySession.userId, `sha256:${sha256Hex(LEGACY_REFRESH_TOKEN)}`]));

  const lcSync = await http.ok('/api/sync', { token: lc.accessToken });
  const byId = new Map<string, any>((lcSync.ciphers ?? []).map((c: any) => [c.id, c]));
  const a = byId.get(allInData);
  assert(a && a.name === enc('legacy-all-in-data') && a.key === enc('legacy-all-in-data-key') && a.reprompt === 1 && a.folderId === lcFolder, `all-in-data cipher: ${JSON.stringify(a)}`);
  const p = byId.get(pascalKeys);
  assert(p && !('Id' in p) && !('Edit' in p) && !('RevisionDate' in p) && p.edit === true, `pascal-keys cipher: ${JSON.stringify(p)}`);
  const s = byId.get(sshAlias);
  assert(s && s.sshKey?.keyFingerprint === enc('legacy-ssh-fingerprint'), `ssh alias cipher: ${JSON.stringify(s)}`);
}

// ---------------------------------------------------------------------------
// Clock adjustments: same stored formats, values moved so the committed
// fixture keeps working (or is in a given state) regardless of when it is used.

async function applyClockAdjustments(): Promise<void> {
  const adjustments = manifest.clockAdjustments as any[];
  await withDb(FIXTURE_DATABASE_URL, async (db) => {
    const run = async (label: string, sql: string, params: unknown[]) => {
      const result = await db.query(sql, params);
      adjustments.push({ label, sql, params, rows: result.rowCount });
    };
    await run('refresh tokens never expire', 'UPDATE refresh_tokens SET expires_at = $1', [FAR_FUTURE_MS]);
    await run('refresh tokens hit their absolute limit far in the future (NULL stays NULL)', 'UPDATE refresh_tokens SET absolute_expires_at = $1 WHERE absolute_expires_at IS NOT NULL', [FAR_FUTURE_MS]);
    await run('trusted 2FA remember tokens never expire', 'UPDATE trusted_two_factor_device_tokens SET expires_at = $1', [FAR_FUTURE_MS]);
    await run('sends are deleted far in the future (ISO text)', 'UPDATE sends SET deletion_date = $1', [FAR_FUTURE_ISO]);
    await run('expiring send expires far in the future (ISO text)', 'UPDATE sends SET expiration_date = $1 WHERE expiration_date IS NOT NULL', [new Date(FAR_FUTURE_MS - 86400000).toISOString()]);
    await run('unused invite expires far in the future', 'UPDATE invites SET expires_at = $1 WHERE code = $2', [FAR_FUTURE_ISO, manifest.features.invites.unused]);
    await run('"expired" invite is expired', 'UPDATE invites SET expires_at = $1 WHERE code = $2', ['2020-01-01T00:00:00.000Z', manifest.features.invites.expired]);
  });
}

// ---------------------------------------------------------------------------
// Outputs

const TRANSIENT_TABLES = ['rate_limit_buckets', 'login_attempts_ip'];

async function writeOutputs(): Promise<void> {
  mkdirSync(FIXTURE_DIR, { recursive: true });
  await applyClockAdjustments();

  await withDb(FIXTURE_DATABASE_URL, async (db) => {
    // Per-IP counters from this run only; the tables stay, their rows go.
    for (const table of TRANSIENT_TABLES) await db.query(`TRUNCATE ${table}`);
    const tables = await db.query<{ table_name: string }>(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name",
    );
    const counts: Record<string, number> = {};
    for (const { table_name } of tables.rows) {
      counts[table_name] = Number((await db.query(`SELECT COUNT(*)::int AS n FROM "${table_name}"`)).rows[0].n);
    }
    manifest.tableCounts = counts;
    manifest.truncatedTransientTables = TRANSIENT_TABLES;
    const config = await db.query<{ key: string }>('SELECT key FROM config ORDER BY key');
    manifest.configKeys = config.rows.map((r) => r.key);
  });

  // pg_dump from the Postgres container (there is no local pg_dump).
  const dump = execFileSync('docker', ['exec', PG_CONTAINER, 'pg_dump', '-U', 'mw', '-d', databaseName(FIXTURE_DATABASE_URL), '--no-owner', '--no-privileges'], {
    maxBuffer: 64 * 1024 * 1024,
    encoding: 'utf8',
  });
  writeFileSync(join(FIXTURE_DIR, 'v1.sql'), normalizeDump(dump));

  if (!backupZip) throw new Error('backup export missing');
  writeFileSync(join(FIXTURE_DIR, 'v1-backup.zip'), backupZip);

  const blobs: Record<string, string> = {};
  for (const key of await listObjectKeys(FIXTURE_BUCKET)) blobs[key] = (await getObject(FIXTURE_BUCKET, key)).toString('base64');
  writeFileSync(join(FIXTURE_DIR, 'blobs.json'), `${JSON.stringify(blobs, null, 2)}\n`);
  manifest.blobs = { count: Object.keys(blobs).length, keys: Object.keys(blobs), layout: { attachment: '<cipherId>/<attachmentId>', sendFile: 'sends/<sendId>/<fileId>' } };

  writeFileSync(join(FIXTURE_DIR, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
}

// Drop the parts of a pg_dump that change with the pg_dump build or run.
function normalizeDump(dump: string): string {
  return dump
    .split('\n')
    .filter((line) => !/^-- Dumped (from database|by pg_dump) version/.test(line))
    // pg_dump >= 17.6 wraps the script in \restrict <random key>; older psql cannot read it.
    .filter((line) => !/^\\(un)?restrict\b/.test(line))
    .join('\n');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
