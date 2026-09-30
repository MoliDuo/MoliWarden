// A database and a backup archive of the earlier version (tests/legacy-fixture,
// written by that version's own code) move onto today's schema with
// scripts/migrate-legacy.ts and scripts/convert-backup-v1.ts, and every
// account and feature in the fixture keeps working afterwards.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import pg from 'pg';
import { createNodeHandler, type NodeHandler } from '../src/main/node';
import { createSecretBox } from '../src/platform/crypto';
import { createDb, createPool } from '../src/platform/db';
import { BackupFormatError, convertBackupArchive } from '../scripts/legacy/backup';
import { MigrationError, migrateLegacy, migrateRemoteIndexes, rollbackLegacy, type MigrationResult } from '../scripts/legacy/migrate';
import {
  FIXTURE_DIR,
  FIXTURE_JWT_SECRET,
  Http,
  WEBAUTHN_RP_NAME,
  passwordGrantFields,
  putObject,
  startFixedYubicoMock,
  yubiKeyOtp,
  type FixedYubicoMock,
} from './legacy-fixture/common';
import { restoreLegacyDump } from './legacy-fixture/restore';
import { nextIp } from './e2e-support';
import { Client, ensureBucket, removeBucket, resetDatabase, TEST_DATABASE_URL, testServerEnv } from './helpers';
import { TotpCodes } from './totp';
import { SoftAuthenticator, SoftCredential, fromB64url } from './webauthn-soft';

const manifest = JSON.parse(readFileSync(join(FIXTURE_DIR, 'manifest.json'), 'utf8'));
const blobs: Record<string, string> = JSON.parse(readFileSync(join(FIXTURE_DIR, 'blobs.json'), 'utf8'));
const accounts = manifest.accounts as Record<string, any>;

const BUCKET = `mw-legacy-${process.pid}`;
const REMOTE_BUCKET = `mw-legacy-remote-${process.pid}`;
const ENV: Record<string, string> = {
  ...testServerEnv(BUCKET),
  WEBAUTHN_RP_NAME,
  BACKUP_ALLOW_PRIVATE_HOSTS: '1',
};
assert.equal(ENV.JWT_SECRET, FIXTURE_JWT_SECRET, 'the backup settings of the fixture open with its JWT_SECRET');

const secrets = createSecretBox(ENV.ENCRYPTION_KEY);
let pool: pg.Pool;
let yubico: FixedYubicoMock;
let app: NodeHandler;
let server: Server;
let origin: string;
let http: Http;
const tokens: Record<string, string> = {};
const totpCodes = new Map<string, TotpCodes>();

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

async function query<T = any>(text: string, params: unknown[] = []): Promise<T[]> {
  return (await pool.query(text, params)).rows as T[];
}

async function restoreFixture(): Promise<void> {
  await resetDatabase();
  await restoreLegacyDump(TEST_DATABASE_URL);
}

async function deploy(): Promise<void> {
  await app?.dispose();
  app = createNodeHandler({ ...ENV, YUBICO_VALIDATION_URLS: yubico.url });
}

const migrate = (dryRun = false) => migrateLegacy(pool, { secrets, jwtSecret: FIXTURE_JWT_SECRET, dryRun });

function grant(key: string, device: string, extra?: Record<string, string>, deviceIdentifier?: string) {
  return http.token(
    passwordGrantFields(accounts[key].email, {
      masterPasswordHash: accounts[key].masterPasswordHash,
      deviceIdentifier: deviceIdentifier ?? `00000000-0000-4000-8000-${createHash('sha256').update(`${key}:${device}`).digest('hex').slice(0, 12)}`,
      extra,
    }),
    { 'X-Forwarded-For': nextIp() },
  );
}

async function totpLogin(key: string, secret: string) {
  const codes = totpCodes.get(key) ?? new TotpCodes();
  totpCodes.set(key, codes);
  const res = await grant(key, 'verify-totp', { twoFactorProvider: '0', twoFactorToken: (await codes.next(secret)).code });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res;
}

// A soft authenticator credential from its manifest export.
function restoreCredential(exported: any): SoftCredential {
  const credential = Object.create(SoftCredential.prototype) as SoftCredential;
  const privateKey = createPrivateKey({ key: Buffer.from(exported.privateKeyPkcs8, 'base64'), format: 'der', type: 'pkcs8' });
  Object.assign(credential, {
    credentialId: fromB64url(exported.credentialId),
    privateKey,
    publicKey: privateKey,
    rpId: exported.rpId,
    userHandle: fromB64url(exported.userHandle),
    prfSeed: Buffer.from(exported.prfSeed, 'base64'),
    counter: exported.counter,
  });
  return credential;
}

function syncCounts(sync: any) {
  const ciphers: any[] = sync.ciphers ?? [];
  return {
    counts: {
      ciphers: ciphers.length,
      deletedCiphers: ciphers.filter((c) => c.deletedDate).length,
      archivedCiphers: ciphers.filter((c) => c.archivedDate).length,
      orgCiphers: ciphers.filter((c) => c.organizationId).length,
      folders: (sync.folders ?? []).length,
      collections: (sync.collections ?? []).length,
      sends: (sync.sends ?? []).length,
      organizations: (sync.profile?.organizations ?? []).length,
      attachments: ciphers.reduce((n, c) => n + (c.attachments?.length ?? 0), 0),
    },
    cipherIds: ciphers.map((c) => c.id).sort(),
  };
}

async function download(url: string): Promise<Buffer> {
  const { pathname, search } = new URL(url);
  const res = await http.fetch(pathname + search);
  assert.equal(res.status, 200);
  return Buffer.from(await res.arrayBuffer());
}

before(async () => {
  pool = createPool({ connectionString: TEST_DATABASE_URL, max: 2 });
  await restoreFixture();
  await ensureBucket(BUCKET);
  await ensureBucket(REMOTE_BUCKET);
  for (const [key, value] of Object.entries(blobs)) await putObject(BUCKET, key, Buffer.from(value, 'base64'));
  yubico = await startFixedYubicoMock();
  await deploy();
  server = createServer((req, res) => void app.handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  // Passkeys of the fixture are bound to the RP id 127.0.0.1.
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  http = new Http(origin);
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  await app?.dispose();
  await yubico?.close();
  await pool?.end();
  await removeBucket(BUCKET).catch(() => undefined);
  await removeBucket(REMOTE_BUCKET).catch(() => undefined);
});

test('the server does not serve a database of the earlier version', async () => {
  const res = await http.call('/identity/accounts/prelogin', { method: 'POST', json: { email: accounts.vault.email } });
  assert.equal(res.status, 503);
  assert.match(res.body.message, /db:migrate-legacy/);
});

test('a dry run converts everything and changes nothing', async () => {
  const result = await migrate(true);
  assert.equal(result.status, 'dry-run');
  assert.equal(result.read.users, manifest.tableCounts.users);
  assert.equal(result.read.ciphers, manifest.tableCounts.ciphers);
  assert.equal(result.written.users, manifest.tableCounts.users);
  const [state] = await query(`SELECT to_regclass('public.config') IS NOT NULL AS config, to_regclass('public.settings') IS NOT NULL AS settings,
                                      EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'legacy') AS legacy`);
  assert.deepEqual(state, { config: true, settings: false, legacy: false });
});

let migration: MigrationResult;

test('the migration carries every row over and reports what it could not', async () => {
  migration = await migrate();
  assert.equal(migration.status, 'migrated');
  assert.deepEqual(
    Object.fromEntries(['users', 'folders', 'ciphers', 'attachments', 'organizations', 'collections', 'sends'].map((t) => [t, migration.written[t]])),
    { users: 19, folders: 5, ciphers: 20, attachments: 4, organizations: 2, collections: 4, sends: 7 },
  );
  const notices = migration.report.notices.join('\n');
  assert.match(notices, new RegExp(`${accounts.legacyApiKey.email}: the API key has to be issued again`));
  // The banned user's devices, and with them its sessions, are left out.
  assert.ok(migration.report.skipped.every((entry) => entry.reason), JSON.stringify(migration.report.skipped));
  const [state] = await query(`SELECT to_regclass('public.config') IS NOT NULL AS config, to_regclass('legacy.config') IS NOT NULL AS legacy`);
  assert.deepEqual(state, { config: false, legacy: true });

  await assert.rejects(migrate(), (error) => error instanceof MigrationError && /migrated already/.test(error.message));
});

test('the secrets are sealed with ENCRYPTION_KEY', async () => {
  const rows = await query(`SELECT data::text AS data FROM two_factor_providers`);
  assert.ok(rows.length >= 4);
  for (const secret of [accounts.totp.twoFactor.totpSecret, accounts.legacyTotp.twoFactor.totpSecret, accounts.vault.apiKey.clientSecret]) {
    const [hit] = await query(
      `SELECT (SELECT count(*) FROM two_factor_providers WHERE data::text LIKE $1) + (SELECT count(*) FROM users WHERE api_key::text LIKE $1) AS n`,
      [`%${secret}%`],
    );
    assert.equal(Number(hit.n), 0, `${secret} is stored in the clear`);
  }
  const [settings] = await query(`SELECT value::text AS value FROM settings WHERE key = 'backup.settings'`);
  assert.doesNotMatch(settings.value, /fixture-s3-secret-access-key|fixture-dav-password/);
});

test('every account signs in with its password', async () => {
  const plain = ['admin', 'vault', 'argon', 'passkey', 'manager', 'custom', 'legacyRawHash', 'legacyApiKey', 'legacyDomains', 'legacyKdf', 'legacyStatus', 'legacySession', 'legacyCipher'];
  for (const key of plain) {
    const res = await grant(key, 'verify');
    assert.equal(res.status, 200, `${key}: ${JSON.stringify(res.body)}`);
    tokens[key] = res.body.access_token;
    const { kdf } = accounts[key];
    assert.equal(res.body.Kdf, kdf.type, key);
    assert.equal(res.body.KdfIterations, kdf.iterations, key);
    if (kdf.type === 1) assert.deepEqual([res.body.KdfMemory, res.body.KdfParallelism], [kdf.memory, kdf.parallelism]);
  }
  const banned = await grant('banned', 'verify');
  assert.notEqual(banned.status, 200);

  const legacy = await http.ok('/identity/accounts/prelogin', { method: 'POST', json: { email: accounts.legacyKdf.email } });
  assert.equal(legacy.kdfIterations ?? legacy.KdfIterations, 5000);
  // The stored password hashes are all in today's format.
  const [raw] = await query(`SELECT count(*)::int AS n FROM users WHERE master_password_hash NOT LIKE '$s$%'`);
  assert.equal(raw.n, 0);
});

test('TOTP: codes, the remembered device and the recovery code keep working', async () => {
  const challenge = await grant('totp', 'verify-totp');
  assert.equal(challenge.status, 400);
  assert.ok(challenge.body.TwoFactorProviders2?.['0'] !== undefined, JSON.stringify(challenge.body));
  await totpLogin('totp', accounts.totp.twoFactor.totpSecret);
  const { rememberToken } = accounts.totp;
  const remembered = await grant('totp', 'remembered', { twoFactorProvider: '5', twoFactorToken: rememberToken.token }, rememberToken.deviceIdentifier);
  assert.equal(remembered.status, 200, JSON.stringify(remembered.body));
  const recovered = await grant('totp', 'verify-recovery', { twoFactorProvider: '8', twoFactorToken: accounts.totp.twoFactor.recoveryCode });
  assert.equal(recovered.status, 200, JSON.stringify(recovered.body));
  tokens.totp = recovered.body.access_token;

  // Stored by an older release: a secret with spaces and lower case, a recovery code without dashes.
  const legacy = accounts.legacyTotp.twoFactor;
  await totpLogin('legacyTotp', legacy.totpSecret);
  const legacyRecovered = await grant('legacyTotp', 'verify-recovery', { twoFactorProvider: '8', twoFactorToken: legacy.recoveryCode.toLowerCase() });
  assert.equal(legacyRecovered.status, 200, JSON.stringify(legacyRecovered.body));
  tokens.legacyTotp = legacyRecovered.body.access_token;
});

test('YubiKey OTP, with the Yubico credentials of the instance', async () => {
  for (const key of ['yubikey', 'legacyYubikey']) {
    const res = await grant(key, 'verify-otp', { twoFactorProvider: '3', twoFactorToken: yubiKeyOtp(accounts[key].twoFactor.yubikeyPublicId) });
    assert.equal(res.status, 200, `${key}: ${JSON.stringify(res.body)}`);
    tokens[key] = res.body.access_token;
  }
});

test('WebAuthn: security keys and account passkeys, with their PRF keys', async () => {
  const credential = restoreCredential(accounts.webauthn2fa.twoFactor.webauthnKeys[0]);
  const challenge = await grant('webauthn2fa', 'verify-webauthn');
  assert.equal(challenge.status, 400);
  const assertion = new SoftAuthenticator().get(challenge.body.TwoFactorProviders2['7'], { origin, style: 'bitwarden' }, credential);
  const res = await grant('webauthn2fa', 'verify-webauthn', { twoFactorProvider: '7', twoFactorToken: JSON.stringify(assertion) });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  tokens.webauthn2fa = res.body.access_token;
  const { rememberToken } = accounts.webauthn2fa;
  const remembered = await grant('webauthn2fa', 'remembered', { twoFactorProvider: '5', twoFactorToken: rememberToken.token }, rememberToken.deviceIdentifier);
  assert.equal(remembered.status, 200);

  for (const passkey of accounts.passkey.passkeys as any[]) {
    const { options, token } = await http.ok('/identity/accounts/webauthn/assertion-options');
    const login = await http.token({
      grant_type: 'webauthn',
      token,
      deviceResponse: JSON.stringify(new SoftAuthenticator().get(options, { origin, userHandle: true }, restoreCredential(passkey))),
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceIdentifier: '00000000-0000-4000-8000-00000000fa55',
      deviceName: 'verify',
    });
    assert.equal(login.status, 200, `${passkey.label}: ${JSON.stringify(login.body)}`);
    assert.equal(login.body.UserDecryptionOptions?.WebAuthnPrfOption?.EncryptedUserKey, passkey.keySet?.encryptedUserKey, passkey.label);
  }
});

test('API keys: a plaintext key carries over, a hashed one has to be issued again', async () => {
  const credentials = (key: string) =>
    http.token({
      grant_type: 'client_credentials',
      client_id: accounts[key].apiKey.clientId,
      client_secret: accounts[key].apiKey.clientSecret,
      scope: 'api',
      deviceType: '21',
      deviceIdentifier: '00000000-0000-4000-8000-0000000a91c1',
      deviceName: 'verify',
    });
  assert.equal((await credentials('vault')).status, 200);
  assert.equal((await credentials('legacyApiKey')).status, 400);
  const shown = await http.ok('/api/accounts/api-key', { method: 'POST', token: tokens.vault, json: { masterPasswordHash: accounts.vault.masterPasswordHash } });
  assert.equal(shown.apiKey, accounts.vault.apiKey.clientSecret);
});

test('signed-in devices stay signed in', async () => {
  const refresh = (token: string, clientId: string) =>
    http.token({ grant_type: 'refresh_token', refresh_token: token, client_id: clientId }, { 'X-Forwarded-For': nextIp() });
  const { mobile, cli, web } = accounts.vault.refreshTokens;
  for (const [token, clientId] of [[mobile, 'mobile'], [cli, 'cli']]) {
    const res = await refresh(token, clientId);
    assert.equal(res.status, 200, `${clientId}: ${JSON.stringify(res.body)}`);
  }
  const cookie = await http.token({ grant_type: 'refresh_token', client_id: 'web' }, {
    'X-Forwarded-For': nextIp(),
    'X-MoliWarden-Web-Session': '1',
    Cookie: `moliwarden_web_refresh=${web}`,
  });
  assert.equal(cookie.status, 200, JSON.stringify(cookie.body));
  // Written before refresh tokens recorded their device and client.
  const legacy = await refresh(accounts.legacySession.legacyRefreshToken, 'cli');
  assert.equal(legacy.status, 200, JSON.stringify(legacy.body));
});

test('equivalent domain rules carry over', async () => {
  const vault = await http.ok('/api/settings/domains', { token: tokens.vault });
  const expected = manifest.features.equivalentDomains.expected;
  assert.deepEqual(
    vault.customEquivalentDomains.map((rule: any) => ({ domains: rule.domains, excluded: rule.excluded })),
    expected.customEquivalentDomains.map((rule: any) => ({ domains: rule.domains, excluded: rule.excluded })),
  );
  assert.deepEqual(
    vault.globalEquivalentDomains.filter((rule: any) => rule.excluded).map((rule: any) => rule.type).sort(),
    [...expected.excludedGlobalTypes].sort(),
  );
  const legacy = await http.ok('/api/settings/domains', { token: tokens.legacyDomains });
  assert.ok(legacy.customEquivalentDomains.some((rule: any) => rule.domains.includes('legacy-mirror.example') && !rule.excluded), JSON.stringify(legacy));
});

test('every vault syncs as before', async () => {
  for (const [key, expected] of Object.entries(manifest.expectations as Record<string, any>)) {
    assert.ok(tokens[key], `no session for ${key}`);
    const got = syncCounts(await http.ok('/api/sync', { token: tokens[key] }));
    assert.deepEqual(got.counts, expected.sync, key);
    assert.deepEqual(got.cipherIds, expected.cipherIds, key);
  }
  // Rows written by older releases: everything inside data, PascalCase keys, the sshKey alias.
  const ids = accounts.legacyCipher.legacyCiphers;
  const sync = await http.ok('/api/sync', { token: tokens.legacyCipher });
  const byId = new Map<string, any>(sync.ciphers.map((c: any) => [c.id, c]));
  const allInData = byId.get(ids.allInData);
  assert.ok(allInData.name && allInData.key, JSON.stringify(allInData));
  assert.equal(allInData.reprompt, 1);
  assert.equal(allInData.folderId, ids.folderId);
  const pascal = byId.get(ids.pascalKeys);
  assert.ok(!('Id' in pascal) && !('Edit' in pascal) && !('RevisionDate' in pascal), JSON.stringify(pascal));
  assert.ok(byId.get(ids.sshAlias).sshKey?.keyFingerprint);
});

test('attachments and Send files download unchanged', async () => {
  for (const attachment of Object.values(manifest.features.attachments as Record<string, any>)) {
    const info = await http.ok(`/api/ciphers/${attachment.cipherId}/attachment/${attachment.attachmentId}`, { token: tokens[attachment.owner] });
    const bytes = await download(info.url);
    assert.equal(bytes.length, attachment.size);
    assert.equal(sha256(bytes), attachment.sha256);
  }
  const file = manifest.features.sends.sends.file;
  const access = await http.ok(`/api/sends/${file.accessId}/access/file/${file.fileId}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: {} });
  assert.equal(sha256(await download(access.url)), file.sha256);
});

test('Sends keep their limits and passwords', async () => {
  const sends = manifest.features.sends.sends;
  const access = (id: string, body: Record<string, unknown> = {}) =>
    http.call(`/api/sends/access/${id}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: body });
  assert.equal((await access(sends['text-accessed'].accessId)).status, 200);
  assert.notEqual((await access(sends['text-max-access-reached'].accessId)).status, 200);
  assert.notEqual((await access(sends['text-disabled'].accessId)).status, 200);
  const locked = sends['text-password'];
  assert.notEqual((await access(locked.accessId)).status, 200);
  assert.equal((await access(locked.accessId, { password: locked.expected.passwordHashB64 })).status, 200);
  const salted = sends['text-password-server-hashed'];
  assert.notEqual((await access(salted.accessId, { password: 'wrong' })).status, 200);
  assert.equal((await access(salted.accessId, { password: salted.expected.password })).status, 200);
});

test('the admin finds users, log settings and backup destinations as they were', async () => {
  const users: any[] = (await http.ok('/api/admin/users', { token: tokens.admin })).data;
  const byEmail = new Map(users.map((user) => [user.email, user]));
  assert.equal(byEmail.get(accounts.banned.email)?.status, 'banned');
  assert.equal(byEmail.get(accounts.legacyStatus.email)?.status, 'active');

  const logs = await http.ok('/api/admin/logs/settings', { token: tokens.admin });
  assert.equal(logs.retentionDays, manifest.features.auditLogSettings.expected.retentionDays);

  // Opened with the JWT_SECRET of the earlier version, sealed again with ENCRYPTION_KEY.
  const settings = await http.ok('/api/admin/backup/settings', { token: tokens.admin });
  const s3 = settings.destinations.find((d: any) => d.type === 's3');
  const dav = settings.destinations.find((d: any) => d.type === 'webdav');
  assert.equal(settings.destinations.length, 2);
  assert.equal(s3.destination.accessKeyId, 'FIXTUREACCESSKEY');
  assert.equal(s3.schedule.intervalHours, 12);
  assert.equal(dav.destination.username, 'fixture-dav-user');
});

test('--migrate-remote-index copies the attachment index of each destination', async () => {
  const saved = await http.call('/api/admin/backup/settings', {
    method: 'PUT',
    token: tokens.admin,
    json: {
      masterPasswordHash: accounts.admin.masterPasswordHash,
      destinations: [
        {
          id: '11111111-1111-4111-8111-111111111111',
          name: 'S3',
          type: 's3',
          includeAttachments: true,
          destination: {
            endpoint: ENV.S3_ENDPOINT,
            bucket: REMOTE_BUCKET,
            region: 'us-east-1',
            accessKeyId: ENV.S3_ACCESS_KEY_ID,
            secretAccessKey: ENV.S3_SECRET_ACCESS_KEY,
            rootPath: 'nightly',
          },
          schedule: { enabled: false, intervalHours: 24, startTime: '03:00', timezone: 'UTC', retentionCount: 2 },
        },
      ],
    },
  });
  assert.equal(saved.status, 200, JSON.stringify(saved.body));
  const index = Buffer.from(JSON.stringify({ version: 1, files: {} }));
  await putObject(REMOTE_BUCKET, 'nightly/attachments/.nodewarden-attachment-index.v1.json', index);

  const db = createDb(pool);
  assert.deepEqual(await migrateRemoteIndexes(db, secrets, true), [{ destination: 'S3', outcome: 'copied' }]);
  assert.deepEqual(await migrateRemoteIndexes(db, secrets, true), [{ destination: 'S3', outcome: 'already copied' }]);
});

test('no rollback once data was written since the migration', async () => {
  await assert.rejects(rollbackLegacy(pool), (error) => error instanceof MigrationError && /written since/.test(error.message));
});

test('a rollback right after the migration puts the earlier tables back', async () => {
  await restoreFixture();
  await migrate();
  await rollbackLegacy(pool);
  const [state] = await query(`SELECT to_regclass('public.config') IS NOT NULL AS config, to_regclass('public.settings') IS NOT NULL AS settings,
                                      EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'legacy') AS legacy`);
  assert.deepEqual(state, { config: true, settings: false, legacy: false });
  const [users] = await query(`SELECT count(*)::int AS n FROM users`);
  assert.equal(users.n, manifest.tableCounts.users);
  await assert.rejects(rollbackLegacy(pool), (error) => error instanceof MigrationError && /no migration to roll back/.test(error.message));
});

test('an empty database is not migrated', async () => {
  await resetDatabase();
  await assert.rejects(migrate(), (error) => error instanceof MigrationError && /no data of the earlier version/.test(error.message));
});

test('a backup archive of the earlier version converts and restores', async () => {
  const { archive, report } = await convertBackupArchive(new Uint8Array(readFileSync(join(FIXTURE_DIR, 'v1-backup.zip'))));
  assert.match(archive.fileName, /^moliwarden_backup_\d{8}_\d{6}_[0-9a-f]{5}\.zip$/);
  assert.equal(archive.manifest.counts.users, manifest.tableCounts.users);
  assert.equal(archive.manifest.counts.ciphers, manifest.tableCounts.ciphers);
  assert.ok(report.notices.some((notice) => /open Backups in the web vault/.test(notice)));
  await assert.rejects(convertBackupArchive(archive.bytes), BackupFormatError);

  // Restored like any backup: onto a fresh instance, by its first admin.
  await resetDatabase();
  await deploy();
  const client = new Client(origin);
  const admin = await client.registerAndLogin('restorer@example.com');
  const form = new FormData();
  form.set('file', new Blob([archive.bytes as Uint8Array<ArrayBuffer>], { type: 'application/zip' }), archive.fileName);
  form.set('masterPasswordHash', Buffer.from('hash-restorer@example.com').toString('base64'));
  form.set('replaceExisting', '1');
  const restored = await admin.request('/api/admin/backup/import', { method: 'POST', body: form });
  assert.equal(restored.status, 200, await restored.clone().text());
  const body = await restored.json();
  assert.equal(body.imported.attachmentFiles, Object.keys(manifest.features.attachments).length);

  const vault = await grant('vault', 'after-restore');
  assert.equal(vault.status, 200, JSON.stringify(vault.body));
  const got = syncCounts(await http.ok('/api/sync', { token: vault.body.access_token }));
  // Sends are not part of backups.
  assert.deepEqual(got.counts, { ...manifest.expectations.vault.sync, sends: 0 });
  assert.deepEqual(got.cipherIds, manifest.expectations.vault.cipherIds);
  const attachment = manifest.features.attachments['login-binary'];
  const info = await http.ok(`/api/ciphers/${attachment.cipherId}/attachment/${attachment.attachmentId}`, { token: vault.body.access_token });
  assert.equal(sha256(await download(info.url)), attachment.sha256);
});
