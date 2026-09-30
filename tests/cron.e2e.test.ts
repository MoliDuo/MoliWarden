// The scheduled job removes what has run out, and only that. Rows are aged
// with SQL: the job must not care how they got old.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { blobExists, cipherPayload, Client, fakeEncString, startTestServer, TEST_DATABASE_URL, type Session, type TestServer } from './helpers';

let server: TestServer;
let client: Client;
let alice: Session;
let db: pg.Client;

const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();
const cron = (secret = 'test-cron-secret') => client.fetch('/api/internal/cron', { headers: { Authorization: `Bearer ${secret}` } });

async function count(table: string, where = 'true'): Promise<number> {
  return Number((await db.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${where}`)).rows[0].n);
}

before(async () => {
  server = await startTestServer();
  client = new Client(server.baseUrl);
  alice = await client.registerAndLogin('alice@example.com');
  db = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await db.connect();
});

after(async () => {
  await db?.end();
  await server?.close();
});

test('only Vercel Cron, with the secret, runs the job', async () => {
  assert.equal((await client.fetch('/api/internal/cron')).status, 401);
  assert.equal((await cron('wrong')).status, 401);
  const response = await cron();
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.object, 'cron');
  assert.deepEqual(body.failed, []);
});

test('expired sessions, tokens, challenges and counters are removed, live ones kept', async () => {
  const old = await client.login('alice@example.com');
  await db.query(`UPDATE refresh_tokens SET expires_at = now() - interval '1 minute' WHERE device_id = (SELECT id FROM devices WHERE identifier = $1)`, [
    old.deviceIdentifier,
  ]);
  for (const [expires, device] of [["now() - interval '1 day'", 'gone'], ["now() + interval '1 day'", 'kept']]) {
    await db.query(
      `INSERT INTO two_factor_remember_tokens (token_hash, user_id, device_identifier, security_stamp, expires_at) SELECT $1, id, $2, security_stamp, ${expires} FROM users`,
      [randomBytes(32), device],
    );
    await db.query(`INSERT INTO webauthn_challenges (challenge_hash, scope, expires_at) VALUES ($1, 'test', ${expires})`, [randomBytes(32)]);
    await db.query(`INSERT INTO consumed_tokens (key, expires_at) VALUES ($1, ${expires})`, [`test:${device}`]);
    await db.query(`INSERT INTO rate_limits (key, count, expires_at) VALUES ($1, 1, ${expires})`, [`test:${device}`]);
  }
  await db.query(`INSERT INTO login_failures (key, failures, locked_until, updated_at) VALUES ('test:stale', 3, NULL, now() - interval '2 days'),
                  ('test:locked', 10, now() + interval '5 minutes', now())`);

  const body = await (await cron()).json();
  assert.deepEqual(body.failed, []);
  assert.ok(body.removed.sessions >= 1);
  assert.ok(body.removed.rememberedDevices >= 1 && body.removed.passkeyChallenges >= 1 && body.removed.usedTokens >= 1);
  assert.ok(body.removed.rateLimits >= 2);

  assert.equal(await count('two_factor_remember_tokens'), 1);
  assert.equal(await count('webauthn_challenges'), 1);
  assert.equal(await count('consumed_tokens', `key LIKE 'test:%'`), 1);
  assert.equal(await count('rate_limits', `key LIKE 'test:%'`), 1);
  assert.deepEqual((await db.query(`SELECT key FROM login_failures WHERE key LIKE 'test:%'`)).rows, [{ key: 'test:locked' }]);

  // The expired session is gone; the current one refreshes.
  const refresh = (token: string) =>
    client.fetch('/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: token, client_id: 'cli' }).toString(),
    });
  assert.equal((await refresh(old.refreshToken)).status, 400);
  const current = await refresh(alice.refreshToken);
  assert.equal(current.status, 200);
  alice.refreshToken = (await current.json()).refresh_token;
});

test('Sends past their deletion date are deleted with their files, and clients are told', async () => {
  const content = Buffer.from('send file contents');
  const created = await alice.json('/api/sends/file/v2', {
    method: 'POST',
    json: { type: 1, name: fakeEncString('f'), key: fakeEncString('k'), file: { fileName: fakeEncString('f.bin') }, fileLength: content.length, deletionDate: inDays(1) },
  });
  const upload = new URL(created.url);
  const put = await client.fetch(upload.pathname + upload.search, { method: 'PUT', headers: { 'x-ms-blob-type': 'BlockBlob' }, body: content });
  assert.equal(put.status, 201);
  const fileKey = `sends/${created.sendResponse.id}/${created.sendResponse.file.id}`;
  assert.equal(await blobExists(fileKey), true);
  const live = await alice.json('/api/sends', {
    method: 'POST',
    json: { type: 0, name: fakeEncString('t'), key: fakeEncString('k'), text: { text: fakeEncString('x'), hidden: false }, deletionDate: inDays(1) },
  });

  await db.query(`UPDATE sends SET deletion_date = now() - interval '1 minute' WHERE id = $1`, [created.sendResponse.id]);
  const revision = await alice.json('/api/accounts/revision-date');
  const body = await (await cron()).json();
  assert.equal(body.removed.sends, 1);

  const sends = (await alice.json('/api/sync')).sends.map((send: any) => send.id);
  assert.deepEqual(sends, [live.id]);
  assert.equal(await blobExists(fileKey), false);
  assert.ok((await alice.json('/api/accounts/revision-date')) > revision);
});

test('attachments whose file never arrived are removed after a while', async () => {
  const cipher = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('with-attachment') });
  const pending = await alice.json(`/api/ciphers/${cipher.id}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('att-key'), fileName: fakeEncString('file'), fileSize: 10 },
  });
  // A fresh one may still be on its way.
  assert.equal((await (await cron()).json()).removed.abandonedUploads, 0);

  await db.query(`UPDATE attachments SET created_at = now() - interval '2 hours' WHERE id = $1`, [pending.attachmentId]);
  const before = await alice.json(`/api/ciphers/${cipher.id}`);
  assert.equal(before.attachments.length, 1);
  const body = await (await cron()).json();
  assert.equal(body.removed.abandonedUploads, 1);
  const afterwards = await alice.json(`/api/ciphers/${cipher.id}`);
  assert.equal(afterwards.attachments, null);
  assert.ok(afterwards.revisionDate > before.revisionDate);
});

test('a second run finds nothing left to remove', async () => {
  const body = await (await cron()).json();
  for (const [task, removed] of Object.entries(body.removed)) {
    if (task !== 'rateLimits') assert.equal(removed, 0, task); // the calls above count against rate limits
  }
});
