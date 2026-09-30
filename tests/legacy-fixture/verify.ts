// Restores the legacy fixture into a fresh database and bucket, starts the
// server against it WITHOUT a schema reset and checks that every account and
// feature listed in manifest.json still works.
//
//   npx tsx tests/legacy-fixture/verify.ts
//
// Exits non-zero when any check fails.
import { createHash, createPrivateKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { unzipSync } from 'fflate';
import {
  FIXTURE_DIR,
  FIXTURE_JWT_SECRET,
  Http,
  PG_CONTAINER,
  S3_ACCESS_KEY_ID,
  S3_ENDPOINT,
  S3_SECRET_ACCESS_KEY,
  SERVER_ROOT,
  VERIFY_BUCKET,
  VERIFY_DATABASE_URL,
  WEBAUTHN_RP_NAME,
  databaseName,
  emptyBucket,
  ensureBucketExists,
  importServerModule,
  prepareServerRoot,
  masterPasswordHash,
  passwordGrantFields,
  putObject,
  recreateDatabase,
  startFixedYubicoMock,
  withDb,
  yubiKeyOtp,
} from './common';
import { SoftAuthenticator, SoftCredential, fromB64url } from '../webauthn-soft';
import { TotpCodes } from '../totp';

// The v1 push relay reads process.env directly (not the env handed to
// createNodeHandler); keep it from calling the real Bitwarden relay.
process.env.PUSH_RELAY_DISABLED = '1';

const manifest = JSON.parse(readFileSync(join(FIXTURE_DIR, 'manifest.json'), 'utf8'));
const blobs: Record<string, string> = JSON.parse(readFileSync(join(FIXTURE_DIR, 'blobs.json'), 'utf8'));

const results: Array<{ name: string; ok: boolean; detail?: string }> = [];

async function check(name: string, fn: () => Promise<void | string>): Promise<void> {
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail: detail || undefined });
  } catch (error) {
    results.push({ name, ok: false, detail: error instanceof Error ? error.message : String(error) });
  }
}

function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

let ipCounter = 0;
function nextIp(): string {
  ipCounter += 1;
  return `10.88.${Math.floor(ipCounter / 250) % 250}.${(ipCounter % 250) + 1}`;
}

// Rebuilds a soft authenticator credential from its manifest export.
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

async function main(): Promise<void> {
  prepareServerRoot();
  const dbName = databaseName(VERIFY_DATABASE_URL);
  console.log(`restoring v1.sql into ${dbName}, blobs into ${VERIFY_BUCKET}, server code from ${SERVER_ROOT}`);
  await recreateDatabase(VERIFY_DATABASE_URL);
  execFileSync('docker', ['exec', '-i', PG_CONTAINER, 'psql', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'mw', '-d', dbName], {
    input: readFileSync(join(FIXTURE_DIR, 'v1.sql')),
    stdio: ['pipe', 'ignore', 'inherit'],
  });
  await ensureBucketExists(VERIFY_BUCKET);
  await emptyBucket(VERIFY_BUCKET);
  for (const [key, value] of Object.entries(blobs)) await putObject(VERIFY_BUCKET, key, Buffer.from(value, 'base64'));

  await check('restored table row counts match manifest.tableCounts', async () => {
    const mismatches: string[] = [];
    await withDb(VERIFY_DATABASE_URL, async (db) => {
      for (const [table, count] of Object.entries(manifest.tableCounts as Record<string, number>)) {
        const n = Number((await db.query(`SELECT COUNT(*)::int AS n FROM "${table}"`)).rows[0].n);
        if (n !== count) mismatches.push(`${table}: ${n} != ${count}`);
      }
    });
    expect(!mismatches.length, mismatches.join(', '));
  });

  const yubico = await startFixedYubicoMock();
  const { createNodeHandler } = await importServerModule<{
    createNodeHandler(source: Record<string, string | undefined>): { handler(req: IncomingMessage, res: ServerResponse): unknown; dispose(): Promise<void> };
  }>('src/main/node.ts');
  const app = createNodeHandler({
    DATABASE_URL: VERIFY_DATABASE_URL,
    JWT_SECRET: FIXTURE_JWT_SECRET,
    S3_ENDPOINT,
    S3_BUCKET: VERIFY_BUCKET,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_REGION: 'us-east-1',
    CRON_SECRET: 'test-cron-secret',
    PUSH_RELAY_DISABLED: '1',
    YUBICO_VALIDATION_URLS: yubico.url,
    WEBAUTHN_RP_NAME,
    SHOW_PASSWORD_HINT: '1',
  });
  const server: Server = createServer((req, res) => void app.handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const http = new Http(origin);

  try {
    await runChecks(http, origin);
  } finally {
    await new Promise((resolve) => setTimeout(resolve, 1000)); // let background tasks finish
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await app.dispose();
    await yubico.close();
  }

  const failed = results.filter((r) => !r.ok);
  for (const r of results) console.log(`${r.ok ? 'ok  ' : 'FAIL'} ${r.name}${r.detail ? ` -- ${r.detail}` : ''}`);
  console.log(`${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) process.exitCode = 1;
}

async function runChecks(http: Http, origin: string): Promise<void> {
  const accounts = manifest.accounts as Record<string, any>;
  const tokens: Record<string, string> = {};
  const totpCodes = new Map<string, TotpCodes>();

  const grant = (key: string, device: string, extra?: Record<string, string>, deviceIdentifier?: string) =>
    http.token(
      passwordGrantFields(accounts[key].email, {
        masterPasswordHash: accounts[key].masterPasswordHash,
        deviceIdentifier: deviceIdentifier ?? `00000000-0000-4000-8000-${createHash('sha256').update(`${key}:${device}`).digest('hex').slice(0, 12)}`,
        extra,
      }),
      { 'X-Forwarded-For': nextIp() },
    );

  // TOTP codes: the restored database already holds replay markers, so retry
  // with the next unused step on a replay refusal.
  async function totpLogin(key: string, secret: string, extra: Record<string, string> = {}) {
    const codes = totpCodes.get(key) ?? new TotpCodes();
    totpCodes.set(key, codes);
    let last: any;
    for (let attempt = 0; attempt < 6; attempt++) {
      last = await grant(key, 'verify-totp', { twoFactorProvider: '0', twoFactorToken: (await codes.next(secret)).code, ...extra });
      if (last.status === 200) return last;
    }
    throw new Error(`TOTP login ${key}: ${last.status} ${JSON.stringify(last.body)}`);
  }

  // --- password logins ------------------------------------------------------

  const plain = ['admin', 'vault', 'argon', 'passkey', 'manager', 'custom', 'legacyRawHash', 'legacyApiKey', 'legacyDomains', 'legacyKdf', 'legacyStatus', 'legacySession', 'legacyCipher'];
  for (const key of plain) {
    await check(`password login: ${key}`, async () => {
      const res = await grant(key, 'verify');
      expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
      tokens[key] = res.body.access_token;
      const kdf = accounts[key].kdf;
      expect(res.body.Kdf === kdf.type && res.body.KdfIterations === kdf.iterations, `kdf ${res.body.Kdf}/${res.body.KdfIterations}`);
      if (kdf.type === 1) expect(res.body.KdfMemory === kdf.memory && res.body.KdfParallelism === kdf.parallelism, 'argon2 params');
    });
  }

  await check('banned user is refused', async () => {
    const res = await grant('banned', 'verify');
    expect(res.status !== 200, `status ${res.status}`);
    return `status ${res.status}`;
  });

  await check('prelogin reports stored KDF (argon, legacyKdf)', async () => {
    const argon = await http.ok('/identity/accounts/prelogin', { method: 'POST', json: { email: accounts.argon.email } });
    expect((argon.kdf ?? argon.Kdf) === 1 && (argon.kdfMemory ?? argon.KdfMemory) === 64 && (argon.kdfParallelism ?? argon.KdfParallelism) === 4, JSON.stringify(argon));
    const legacy = await http.ok('/identity/accounts/prelogin', { method: 'POST', json: { email: accounts.legacyKdf.email } });
    expect((legacy.kdfIterations ?? legacy.KdfIterations) === 5000, JSON.stringify(legacy));
  });

  await check('master password hint stored (vault)', async () => {
    const hint = await withDb(VERIFY_DATABASE_URL, async (db) => (await db.query('SELECT master_password_hint FROM users WHERE email = $1', [accounts.vault.email])).rows[0]?.master_password_hint);
    expect(hint === accounts.vault.masterPasswordHint, `hint ${hint}`);
  });

  // --- two-factor -----------------------------------------------------------

  await check('TOTP: challenge, code, remember token, recovery code (totp)', async () => {
    const challenge = await grant('totp', 'verify-totp');
    expect(challenge.status === 400 && challenge.body.TwoFactorProviders2?.['0'] !== undefined, `challenge ${JSON.stringify(challenge.body)}`);
    const ok = await totpLogin('totp', accounts.totp.twoFactor.totpSecret);
    tokens.totp = ok.body.access_token;
    const remembered = await grant('totp', 'remembered', { twoFactorProvider: '5', twoFactorToken: accounts.totp.rememberToken.token }, accounts.totp.rememberToken.deviceIdentifier);
    expect(remembered.status === 200, `remember ${remembered.status} ${JSON.stringify(remembered.body)}`);
    const recovered = await grant('totp', 'verify-recovery', { twoFactorProvider: '8', twoFactorToken: accounts.totp.twoFactor.recoveryCode });
    expect(recovered.status === 200, `recovery ${recovered.status} ${JSON.stringify(recovered.body)}`);
    // Using the recovery code turns 2FA off and rotates the security stamp.
    tokens.totp = recovered.body.access_token;
  });

  await check('YubiKey OTP login (yubikey)', async () => {
    const challenge = await grant('yubikey', 'verify-otp');
    expect(challenge.status === 400 && challenge.body.TwoFactorProviders2?.['3'] !== undefined, `challenge ${JSON.stringify(challenge.body)}`);
    const res = await grant('yubikey', 'verify-otp', { twoFactorProvider: '3', twoFactorToken: yubiKeyOtp(accounts.yubikey.twoFactor.yubikeyPublicId) });
    expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
    tokens.yubikey = res.body.access_token;
  });

  await check('WebAuthn 2FA: security key assertion and remember token (webauthn2fa)', async () => {
    const key = accounts.webauthn2fa.twoFactor.webauthnKeys[0];
    const credential = restoreCredential(key);
    const challenge = await grant('webauthn2fa', 'verify-webauthn');
    expect(challenge.status === 400 && challenge.body.TwoFactorProviders2?.['7'], `challenge ${JSON.stringify(challenge.body)}`);
    const assertion = new SoftAuthenticator().get(challenge.body.TwoFactorProviders2['7'], { origin, style: 'bitwarden' }, credential);
    const res = await grant('webauthn2fa', 'verify-webauthn', { twoFactorProvider: '7', twoFactorToken: JSON.stringify(assertion) });
    expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
    tokens.webauthn2fa = res.body.access_token;
    const remembered = await grant('webauthn2fa', 'remembered', { twoFactorProvider: '5', twoFactorToken: accounts.webauthn2fa.rememberToken.token }, accounts.webauthn2fa.rememberToken.deviceIdentifier);
    expect(remembered.status === 200, `remember ${remembered.status}`);
  });

  for (const passkey of accounts.passkey.passkeys as any[]) {
    await check(`account passkey login: ${passkey.label}`, async () => {
      const credential = restoreCredential(passkey);
      const { options, token } = await http.ok('/identity/accounts/webauthn/assertion-options');
      const assertion = new SoftAuthenticator().get(options, { origin, userHandle: true }, credential);
      const res = await http.token({
        grant_type: 'webauthn',
        token,
        deviceResponse: JSON.stringify(assertion),
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceIdentifier: '00000000-0000-4000-8000-00000000fa55',
        deviceName: 'verify',
      });
      expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
      const prf = res.body.UserDecryptionOptions?.WebAuthnPrfOption;
      if (passkey.keySet) expect(prf?.EncryptedUserKey === passkey.keySet.encryptedUserKey, `PRF option ${JSON.stringify(prf)}`);
      else expect(!prf, `unexpected PRF option ${JSON.stringify(prf)}`);
    });
  }

  // --- API keys and refresh tokens -----------------------------------------

  for (const key of ['vault', 'legacyApiKey']) {
    await check(`API key client_credentials: ${key} (${accounts[key].apiKey.storedFormat})`, async () => {
      const res = await http.token({
        grant_type: 'client_credentials',
        client_id: accounts[key].apiKey.clientId,
        client_secret: accounts[key].apiKey.clientSecret,
        scope: 'api',
        deviceType: '21',
        deviceIdentifier: '00000000-0000-4000-8000-0000000a91c1',
        deviceName: 'verify',
      });
      expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
    });
  }

  await check('API key view: plaintext readable (vault), legacy hash 409 (legacyApiKey)', async () => {
    const vault = await http.ok('/api/accounts/api-key', { method: 'POST', token: tokens.vault, json: { masterPasswordHash: masterPasswordHash(accounts.vault.email) } });
    expect(vault.apiKey === accounts.vault.apiKey.clientSecret, 'vault api key differs');
    const legacy = await http.call('/api/accounts/api-key', { method: 'POST', token: tokens.legacyApiKey, json: { masterPasswordHash: masterPasswordHash(accounts.legacyApiKey.email) } });
    expect(legacy.status === 409, `legacy status ${legacy.status}`);
  });

  await check('refresh tokens: mobile, cli, web cookie (vault)', async () => {
    const { mobile, cli, web } = accounts.vault.refreshTokens;
    for (const [label, token, clientId] of [['mobile', mobile, 'mobile'], ['cli', cli, 'cli']] as const) {
      const res = await http.token({ grant_type: 'refresh_token', refresh_token: token, client_id: clientId }, { 'X-Forwarded-For': nextIp() });
      expect(res.status === 200 && res.body.access_token, `${label}: ${res.status} ${JSON.stringify(res.body)}`);
    }
    const res = await http.token({ grant_type: 'refresh_token', client_id: 'web' }, {
      'X-Forwarded-For': nextIp(),
      'X-MoliWarden-Web-Session': '1',
      Cookie: `moliwarden_web_refresh=${web}`,
    });
    expect(res.status === 200 && res.body.access_token, `web: ${res.status} ${JSON.stringify(res.body)}`);
  });

  // --- legacy variants --------------------------------------------------------

  await check('legacy refresh token with NULL stamps/client type (legacySession)', async () => {
    const res = await http.token({ grant_type: 'refresh_token', refresh_token: accounts.legacySession.legacyRefreshToken, client_id: 'cli' }, { 'X-Forwarded-For': nextIp() });
    expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
  });

  await check('legacy un-normalized TOTP secret and recovery code (legacyTotp)', async () => {
    const tf = accounts.legacyTotp.twoFactor;
    const ok = await totpLogin('legacyTotp', tf.totpSecret);
    tokens.legacyTotp = ok.body.access_token;
    const recovered = await grant('legacyTotp', 'verify-recovery', { twoFactorProvider: '8', twoFactorToken: tf.recoveryCode.toLowerCase() });
    expect(recovered.status === 200, `recovery ${recovered.status} ${JSON.stringify(recovered.body)}`);
    tokens.legacyTotp = recovered.body.access_token;
  });

  await check('legacy upper-case padded YubiKey id (legacyYubikey)', async () => {
    const res = await grant('legacyYubikey', 'verify-otp', { twoFactorProvider: '3', twoFactorToken: yubiKeyOtp(accounts.legacyYubikey.twoFactor.yubikeyPublicId) });
    expect(res.status === 200, `${res.status} ${JSON.stringify(res.body)}`);
    tokens.legacyYubikey = res.body.access_token;
  });

  await check('legacy equivalent_domains-only settings (legacyDomains)', async () => {
    const body = await http.ok('/api/settings/domains', { token: tokens.legacyDomains });
    const rules = body.customEquivalentDomains ?? body.CustomEquivalentDomains ?? [];
    expect(rules.some((r: any) => (r.domains ?? r.Domains ?? []).includes('legacy-mirror.example') && !(r.excluded ?? r.Excluded)), JSON.stringify(body));
  });

  await check('equivalent domains: custom + excluded global (vault)', async () => {
    const body = await http.ok('/api/settings/domains', { token: tokens.vault });
    const expected = manifest.features.equivalentDomains.expected;
    const custom = body.customEquivalentDomains ?? body.CustomEquivalentDomains;
    expect(JSON.stringify(custom) === JSON.stringify(expected.customEquivalentDomains), `custom ${JSON.stringify(custom)}`);
    const globals: any[] = body.globalEquivalentDomains ?? body.GlobalEquivalentDomains ?? [];
    const excluded = globals.filter((g) => g.excluded ?? g.Excluded).map((g) => g.type ?? g.Type).sort();
    expect(JSON.stringify(excluded) === JSON.stringify([...expected.excludedGlobalTypes].sort()), `excluded ${JSON.stringify(excluded)}`);
  });

  await check('legacy cipher rows read back (legacyCipher)', async () => {
    const ids = accounts.legacyCipher.legacyCiphers;
    const sync = await http.ok('/api/sync', { token: tokens.legacyCipher });
    const byId = new Map<string, any>((sync.ciphers ?? []).map((c: any) => [c.id, c]));
    const a = byId.get(ids.allInData);
    expect(a?.name && a.key && a.reprompt === 1 && a.folderId === ids.folderId, `all-in-data ${JSON.stringify(a)}`);
    const p = byId.get(ids.pascalKeys);
    expect(p && !('Id' in p) && !('Edit' in p) && !('RevisionDate' in p), `pascal ${JSON.stringify(p)}`);
    const s = byId.get(ids.sshAlias);
    expect(s?.sshKey?.keyFingerprint, `ssh ${JSON.stringify(s)}`);
  });

  // --- vault contents -----------------------------------------------------

  for (const [key, expected] of Object.entries(manifest.expectations as Record<string, any>)) {
    await check(`sync matches manifest: ${key}`, async () => {
      expect(tokens[key], 'no session');
      const sync = await http.ok('/api/sync', { token: tokens[key] });
      const ciphers: any[] = sync.ciphers ?? [];
      const got = {
        ciphers: ciphers.length,
        deletedCiphers: ciphers.filter((c) => c.deletedDate).length,
        archivedCiphers: ciphers.filter((c) => c.archivedDate).length,
        orgCiphers: ciphers.filter((c) => c.organizationId).length,
        folders: (sync.folders ?? []).length,
        collections: (sync.collections ?? []).length,
        sends: (sync.sends ?? []).length,
        organizations: (sync.profile?.organizations ?? []).length,
        attachments: ciphers.reduce((n, c) => n + (c.attachments?.length ?? 0), 0),
      };
      expect(JSON.stringify(got) === JSON.stringify(expected.sync), `got ${JSON.stringify(got)} expected ${JSON.stringify(expected.sync)}`);
      const ids = ciphers.map((c) => c.id).sort();
      expect(JSON.stringify(ids) === JSON.stringify(expected.cipherIds), 'cipher ids differ');
    });
  }

  for (const [label, attachment] of Object.entries(manifest.features.attachments as Record<string, any>)) {
    await check(`attachment bytes: ${label}`, async () => {
      const info = await http.ok(`/api/ciphers/${attachment.cipherId}/attachment/${attachment.attachmentId}`, { token: tokens[attachment.owner] });
      const url = new URL(info.url);
      const res = await http.fetch(url.pathname + url.search);
      expect(res.status === 200, `download ${res.status}`);
      const bytes = Buffer.from(await res.arrayBuffer());
      expect(bytes.length === attachment.size && sha256(bytes) === attachment.sha256, 'content differs');
      expect(sha256(Buffer.from(blobs[attachment.objectKey], 'base64')) === attachment.sha256, 'blobs.json differs');
    });
  }

  const sends = manifest.features.sends.sends;
  await check('send file download', async () => {
    const file = sends.file;
    const access = await http.ok(`/api/sends/${file.accessId}/access/file/${file.fileId}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: {} });
    const url = new URL(access.url);
    const res = await http.fetch(url.pathname + url.search);
    const bytes = Buffer.from(await res.arrayBuffer());
    expect(res.status === 200 && sha256(bytes) === file.sha256, `download ${res.status}`);
  });
  await check('send access: open, exhausted, disabled, password-protected', async () => {
    const access = (id: string, body: Record<string, unknown> = {}) => http.call(`/api/sends/access/${id}`, { method: 'POST', headers: { 'X-Forwarded-For': nextIp() }, json: body });
    const open = await access(sends['text-accessed'].accessId);
    expect(open.status === 200, `open ${open.status}`);
    const exhausted = await access(sends['text-max-access-reached'].accessId);
    expect(exhausted.status !== 200, `exhausted ${exhausted.status}`);
    const disabled = await access(sends['text-disabled'].accessId);
    expect(disabled.status !== 200, `disabled ${disabled.status}`);
    const locked = await access(sends['text-password'].accessId);
    expect(locked.status !== 200, `password-protected without password ${locked.status}`);
    const unlocked = await access(sends['text-password'].accessId, { password: sends['text-password'].expected.passwordHashB64 });
    expect(unlocked.status === 200, `password-protected with hash ${unlocked.status} ${JSON.stringify(unlocked.body)}`);
  });

  await check('v1-backup.zip holds db.json, manifest.json and every attachment blob', async () => {
    const zipped = unzipSync(new Uint8Array(readFileSync(join(FIXTURE_DIR, 'v1-backup.zip'))));
    const entries = Object.keys(zipped).sort();
    expect(JSON.stringify(entries) === JSON.stringify(manifest.features.backupExport.entries), `entries ${entries.join(', ')}`);
    const db = JSON.parse(Buffer.from(zipped['db.json']).toString('utf8'));
    expect(db && typeof db === 'object', 'db.json');
    for (const attachment of Object.values(manifest.features.attachments as Record<string, any>)) {
      const bytes = zipped[`attachments/${attachment.cipherId}/${attachment.attachmentId}.bin`];
      expect(bytes && sha256(Buffer.from(bytes)) === attachment.sha256, `attachment ${attachment.objectKey}`);
    }
    return `${entries.length} entries`;
  });

  // --- admin ----------------------------------------------------------------

  await check('backup settings decrypt with S3 + WebDAV credentials (admin)', async () => {
    const settings = await http.ok('/api/admin/backup/settings', { token: tokens.admin });
    const destinations: any[] = settings.destinations ?? [];
    expect(destinations.length === 2, `destinations ${destinations.length}`);
    const s3 = destinations.find((d) => d.type === 's3');
    const dav = destinations.find((d) => d.type === 'webdav');
    expect(s3?.destination?.accessKeyId === 'FIXTUREACCESSKEY' && s3.schedule?.intervalHours === 12, `s3 ${JSON.stringify(s3)}`);
    expect(dav?.destination?.username === 'fixture-dav-user', `webdav ${JSON.stringify(dav)}`);
  });

  await check('audit logs and log settings (admin)', async () => {
    const settings = await http.ok('/api/admin/logs/settings', { token: tokens.admin });
    expect(settings.retentionDays === manifest.features.auditLogSettings.expected.retentionDays, JSON.stringify(settings));
  });

  await check('admin user list: banned + non-canonical status', async () => {
    const list = await http.ok('/api/admin/users', { token: tokens.admin });
    const users: any[] = Array.isArray(list) ? list : list.data ?? list.users ?? [];
    const byEmail = new Map(users.map((u) => [u.email, u]));
    expect(byEmail.get(accounts.banned.email)?.status === 'banned', 'banned status');
    expect(byEmail.get(accounts.legacyStatus.email)?.status === 'active', 'legacy status not active');
    return `${users.length} users`;
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
