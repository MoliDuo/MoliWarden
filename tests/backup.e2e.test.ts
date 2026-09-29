// Instance backups: settings, local export and restore, and runs to S3 and
// WebDAV destinations with their browsing, restore and scheduling.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { unzipSync, zipSync } from 'fflate';
import pg from 'pg';
import { masterPasswordHash } from './e2e-support';
import {
  blobExists,
  Client,
  cipherPayload,
  ensureBucket,
  fakeEncString,
  removeBucket,
  startTestServer,
  TEST_DATABASE_URL,
  type Session,
  type TestServer,
} from './helpers';
import { startFakeWebDav, type FakeWebDav } from './webdav-fake';

const ADMIN = 'alice@example.com';
const PASSWORD = masterPasswordHash(ADMIN);
const REMOTE_BUCKET = `mw-backup-${process.pid}`;
const S3_ID = '11111111-1111-4111-8111-111111111111';
const DAV_ID = '22222222-2222-4222-8222-222222222222';

let server: TestServer;
let client: Client;
let alice: Session;
let dav: FakeWebDav;
let db: pg.Client;
let cipherId: string;
let attachmentId: string;
const attachmentBytes = Buffer.from('encrypted-attachment-'.repeat(50));

const s3Destination = (schedule: Record<string, unknown> = {}) => ({
  id: S3_ID,
  name: 'S3',
  type: 's3',
  includeAttachments: true,
  destination: {
    endpoint: 'http://localhost:58333',
    bucket: REMOTE_BUCKET,
    region: 'us-east-1',
    accessKeyId: 'mwaccess',
    secretAccessKey: 'mwsecret123',
    rootPath: 'nightly',
  },
  schedule: { enabled: false, intervalHours: 24, startTime: '03:00', timezone: 'UTC', retentionCount: 2, ...schedule },
});

const davDestination = () => ({
  id: DAV_ID,
  name: 'WebDAV',
  type: 'webdav',
  includeAttachments: true,
  destination: { baseUrl: dav.url, username: 'dav', password: 'dav-secret', remotePath: 'backups/mw' },
  schedule: { enabled: false, intervalHours: 24, startTime: '03:00', timezone: 'UTC', retentionCount: 5 },
});

async function saveSettings(destinations: unknown[]) {
  const response = await alice.request('/api/admin/backup/settings', { method: 'PUT', json: { destinations, masterPasswordHash: PASSWORD } });
  assert.equal(response.status, 200, await response.clone().text());
  return response.json();
}

const fileNameOf = (response: Response) => /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ?? '';
const checksum = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex').slice(0, 5);

function importForm(bytes: Uint8Array<ArrayBuffer>, fileName: string, fields: Record<string, string> = {}) {
  const form = new FormData();
  form.set('file', new Blob([bytes], { type: 'application/zip' }), fileName);
  form.set('masterPasswordHash', PASSWORD);
  for (const [name, value] of Object.entries(fields)) form.set(name, value);
  return form;
}

// A restore ends every session and leaves the settings for an admin to
// repair; this signs in again and repairs them.
async function afterRestore() {
  alice = await client.login(ADMIN);
  const settings = await alice.request('/api/admin/backup/settings');
  assert.equal(settings.status, 409);
  assert.match((await settings.json()).message, /reactivation after restore/);
  const state = await alice.json('/api/admin/backup/settings/repair');
  assert.equal(state.needsRepair, true);
  const repaired = await alice.request('/api/admin/backup/settings/repair', {
    method: 'POST',
    json: { destinations: [s3Destination(), davDestination()], masterPasswordHash: PASSWORD },
  });
  assert.equal(repaired.status, 200, await repaired.clone().text());
  assert.equal((await alice.json('/api/admin/backup/settings/repair')).needsRepair, false);
}

async function runBackup(destinationId: string) {
  const response = await alice.request('/api/admin/backup/run', { method: 'POST', json: { destinationId, masterPasswordHash: PASSWORD } });
  assert.equal(response.status, 200, await response.clone().text());
  return response.json();
}

async function remoteArchives(destinationId: string): Promise<string[]> {
  const listing = await alice.json(`/api/admin/backup/remote?destinationId=${destinationId}`);
  assert.equal(listing.object, 'backup-remote-browser');
  return listing.items.filter((item: any) => !item.isDirectory).map((item: any) => item.path);
}

before(async () => {
  server = await startTestServer({ env: { BACKUP_ALLOW_PRIVATE_HOSTS: '1' } });
  client = new Client(server.baseUrl);
  alice = await client.registerAndLogin(ADMIN);
  await ensureBucket(REMOTE_BUCKET);
  dav = await startFakeWebDav('dav', 'dav-secret');
  db = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await db.connect();

  const folder = await alice.json('/api/folders', { method: 'POST', json: { name: fakeEncString('folder') } });
  const cipher = await alice.json('/api/ciphers', { method: 'POST', json: cipherPayload('backed-up', { folderId: folder.id }) });
  cipherId = cipher.id;
  const meta = await alice.json(`/api/ciphers/${cipherId}/attachment/v2`, {
    method: 'POST',
    json: { key: fakeEncString('att-key'), fileName: fakeEncString('file'), fileSize: attachmentBytes.length },
  });
  attachmentId = meta.attachmentId;
  const upload = new URL(meta.url);
  const put = await client.fetch(upload.pathname + upload.search, { method: 'PUT', headers: { 'x-ms-blob-type': 'BlockBlob' }, body: attachmentBytes });
  assert.equal(put.status, 201);
});

after(async () => {
  await db?.end();
  await dav?.close();
  await removeBucket(REMOTE_BUCKET).catch(() => undefined);
  await server?.close();
});

test('settings start empty, are checked, and never show secrets', async () => {
  assert.deepEqual(await alice.json('/api/admin/backup/settings'), { destinations: [] });

  const unconfirmed = await alice.request('/api/admin/backup/settings', { method: 'PUT', json: { destinations: [] } });
  assert.equal(unconfirmed.status, 400);
  const badInterval = await alice.request('/api/admin/backup/settings', {
    method: 'PUT',
    json: { destinations: [s3Destination({ intervalHours: 100 })], masterPasswordHash: PASSWORD },
  });
  assert.equal(badInterval.status, 400);
  assert.equal((await badInterval.json()).message, 'Backup interval hours must be between 1 and 99');

  const saved = await saveSettings([s3Destination(), davDestination()]);
  assert.equal(saved.destinations[0].destination.secretAccessKey, '********');
  assert.equal(saved.destinations[1].destination.password, '********');
  assert.equal(saved.destinations[0].destination.endpoint, 'http://localhost:58333');

  // Sending the redacted value back keeps the secret; an empty one clears it.
  const cleared = { ...davDestination(), destination: { ...davDestination().destination, password: '' } };
  const kept = { ...s3Destination(), destination: { ...s3Destination().destination, secretAccessKey: '********' } };
  const next = await saveSettings([kept, cleared]);
  assert.equal(next.destinations[0].destination.secretAccessKey, '********');
  assert.equal(next.destinations[1].destination.password, '');
  const refused = await alice.request('/api/admin/backup/run', { method: 'POST', json: { destinationId: DAV_ID, masterPasswordHash: PASSWORD } });
  assert.equal(refused.status, 400);
  assert.equal((await refused.json()).message, 'WebDAV password is required');
  await saveSettings([kept, davDestination()]);

  const missing = await alice.request('/api/admin/backup/run', { method: 'POST', json: { destinationId: crypto.randomUUID(), masterPasswordHash: PASSWORD } });
  assert.equal(missing.status, 404);
  assert.equal((await missing.json()).message, 'Backup destination not found');
});

test('export, attachment files, and local restore', async () => {
  const exported = await alice.request('/api/admin/backup/export', { method: 'POST', json: { includeAttachments: true, masterPasswordHash: PASSWORD } });
  assert.equal(exported.status, 200, await exported.clone().text());
  assert.equal(exported.headers.get('Content-Type'), 'application/zip');
  const bytes = new Uint8Array(await exported.arrayBuffer());
  const fileName = fileNameOf(exported);
  assert.match(fileName, /^moliwarden_backup_\d{8}_\d{6}_[0-9a-f]{5}\.zip$/);
  assert.ok(fileName.endsWith(`_${checksum(bytes)}.zip`));

  const entries = unzipSync(bytes);
  const manifest = JSON.parse(new TextDecoder().decode(entries['manifest.json']));
  const dump = JSON.parse(new TextDecoder().decode(entries['vault.json']));
  assert.equal(manifest.formatVersion, 2);
  assert.deepEqual(manifest.attachmentBlobs.map((ref: any) => ref.blobName), [`${cipherId}/${attachmentId}`]);
  assert.equal(dump.users.length, 1);
  assert.equal(dump.users[0].apiKey, undefined);
  assert.ok(!('sends' in dump) && !('devices' in dump) && !('refreshTokens' in dump));
  // Settings go in only in their portable form.
  const settings = dump.settings.find((record: any) => record.key === 'backup.settings');
  assert.equal(JSON.parse(settings.value).runtime, null);
  assert.ok(!JSON.stringify(dump).includes('mwsecret123'));

  // Credentials never go in a URL.
  assert.equal((await alice.request('/api/admin/backup/blob')).status, 405);
  const blob = await alice.request('/api/admin/backup/blob', { method: 'POST', json: { blobName: `${cipherId}/${attachmentId}`, masterPasswordHash: PASSWORD } });
  assert.equal(blob.status, 200);
  const file = Buffer.from(await blob.arrayBuffer());
  assert.deepEqual(file, attachmentBytes);
  const invalid = await alice.request('/api/admin/backup/blob', { method: 'POST', json: { blobName: '../x', masterPasswordHash: PASSWORD } });
  assert.equal(invalid.status, 400);

  // Without replaceExisting, only an empty server is restored onto.
  const refused = await alice.request('/api/admin/backup/import', { method: 'POST', body: importForm(bytes, fileName) });
  assert.equal(refused.status, 409);
  assert.match((await refused.json()).message, /fresh instance/);
  const tampered = await alice.request('/api/admin/backup/import', {
    method: 'POST',
    body: importForm(bytes, fileName.replace(/_[0-9a-f]{5}\.zip$/, '_00000.zip'), { replaceExisting: '1' }),
  });
  assert.equal(tampered.status, 400);
  assert.equal((await tampered.json()).message, 'Backup file checksum does not match its filename');

  // The server's archive refers to the files; restored alone, they are skipped.
  const skipped = await alice.request('/api/admin/backup/import', { method: 'POST', body: importForm(bytes, fileName, { replaceExisting: '1' }) });
  assert.equal(skipped.status, 200, await skipped.clone().text());
  const skippedBody = await skipped.json();
  assert.equal(skippedBody.skipped.attachments, 1);
  assert.equal(skippedBody.imported.attachments, 0);
  assert.equal(await blobExists(`${cipherId}/${attachmentId}`), false);
  alice = await client.login(ADMIN);

  // The web vault adds the files to the archive, as the client export does.
  entries[`attachments/${cipherId}/${attachmentId}.bin`] = new Uint8Array(file);
  const full = zipSync(entries, { level: 0 });
  const fullName = fileName.replace(/_[0-9a-f]{5}\.zip$/, `_${checksum(full)}.zip`);
  const restored = await alice.request('/api/admin/backup/import', { method: 'POST', body: importForm(full, fullName, { replaceExisting: '1' }) });
  assert.equal(restored.status, 200, await restored.clone().text());
  const body = await restored.json();
  assert.equal(body.object, 'instance-backup-import');
  assert.deepEqual(
    { users: body.imported.users, folders: body.imported.folders, ciphers: body.imported.ciphers, files: body.imported.attachmentFiles },
    { users: 1, folders: 1, ciphers: 1, files: 1 },
  );
  assert.equal(body.skipped.attachments, 0);

  await afterRestore();
  const sync = await alice.json('/api/sync');
  assert.equal(sync.ciphers.length, 1);
  assert.equal(sync.ciphers[0].attachments.length, 1);
  assert.equal(await blobExists(`${cipherId}/${attachmentId}`), true);
});

test('a malformed archive is refused', async () => {
  const junk = new TextEncoder().encode('not a zip');
  const response = await alice.request('/api/admin/backup/import', { method: 'POST', body: importForm(junk, 'junk.zip', { replaceExisting: '1' }) });
  assert.equal(response.status, 400);
  assert.match((await response.json()).message, /^Invalid backup/);
  const notMultipart = await alice.request('/api/admin/backup/import', { method: 'POST', json: {} });
  assert.equal(notMultipart.status, 400);
  assert.equal((await notMultipart.json()).message, 'Content-Type must be multipart/form-data');
});

test('runs to S3 upload attachments once and keep the newest archives', async () => {
  const first = await runBackup(S3_ID);
  assert.equal(first.object, 'backup-run');
  assert.equal(first.result.provider, 's3');
  assert.equal(first.result.remotePath, `nightly/${first.result.fileName}`);
  assert.ok(first.settings.destinations[0].runtime.lastSuccessAt);
  assert.equal(first.settings.destinations[0].destination.secretAccessKey, '********');
  const listing = await alice.json(`/api/admin/backup/remote?destinationId=${S3_ID}`);
  assert.deepEqual(listing.items.filter((item: any) => item.isDirectory).map((item: any) => item.path), ['attachments']);
  const files = await alice.json(`/api/admin/backup/remote?destinationId=${S3_ID}&path=attachments/${cipherId}`);
  assert.deepEqual(files.items.map((item: any) => item.name), [attachmentId]);
  assert.equal(files.parentPath, 'attachments');

  // Unchanged files are not uploaded again: removing one remotely goes unnoticed.
  await fetchRemoteDelete(`nightly/attachments/${cipherId}/${attachmentId}`);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  await runBackup(S3_ID);
  const again = await alice.json(`/api/admin/backup/remote?destinationId=${S3_ID}&path=attachments/${cipherId}`);
  assert.deepEqual(again.items, []);

  // retentionCount is 2. Archives are ordered by time, to the second.
  await new Promise((resolve) => setTimeout(resolve, 1100));
  await runBackup(S3_ID);
  const archives = await remoteArchives(S3_ID);
  assert.equal(archives.length, 2);
  assert.ok(!archives.includes(first.result.fileName));
});

// Deletes an object in the remote bucket behind the server's back.
async function fetchRemoteDelete(key: string) {
  const { AwsClient } = await import('aws4fetch');
  const aws = new AwsClient({ accessKeyId: 'mwaccess', secretAccessKey: 'mwsecret123', region: 'us-east-1', service: 's3' });
  const response = await aws.fetch(`http://localhost:58333/${REMOTE_BUCKET}/${key}`, { method: 'DELETE' });
  assert.ok(response.ok);
}

test('remote archives can be checked, downloaded, restored and deleted', async () => {
  const run = await runBackup(DAV_ID);
  assert.equal(run.result.provider, 'webdav');
  assert.equal(run.result.remotePath, `backups/mw/${run.result.fileName}`);
  assert.ok(dav.files.has(`backups/mw/attachments/${cipherId}/${attachmentId}`));
  const path = run.result.fileName;
  assert.deepEqual(await remoteArchives(DAV_ID), [path]);

  const integrity = await alice.json('/api/admin/backup/remote/integrity', { method: 'POST', json: { destinationId: DAV_ID, path, masterPasswordHash: PASSWORD } });
  assert.equal(integrity.object, 'backup-remote-integrity');
  assert.equal(integrity.integrity.matches, true);
  const download = await alice.request('/api/admin/backup/remote/download', { method: 'POST', json: { destinationId: DAV_ID, path, masterPasswordHash: PASSWORD } });
  assert.equal(download.status, 200);
  assert.equal(fileNameOf(download), path);
  assert.equal(checksum(new Uint8Array(await download.arrayBuffer())), path.slice(-9, -4));
  const traversal = await alice.request('/api/admin/backup/remote/download', { method: 'POST', json: { destinationId: DAV_ID, path: '../x.zip', masterPasswordHash: PASSWORD } });
  assert.equal(traversal.status, 400);
  assert.equal((await traversal.json()).message, 'Invalid remote backup path');
  const notZip = await alice.request('/api/admin/backup/remote/download', { method: 'POST', json: { destinationId: DAV_ID, path: 'x.txt', masterPasswordHash: PASSWORD } });
  assert.equal((await notZip.json()).message, 'Please select a backup ZIP file');

  // The attachment files come from the destination.
  await alice.request(`/api/ciphers/${cipherId}/attachment/${attachmentId}`, { method: 'DELETE' });
  assert.equal(await blobExists(`${cipherId}/${attachmentId}`), false);
  const restored = await alice.request('/api/admin/backup/remote/restore', {
    method: 'POST',
    json: { destinationId: DAV_ID, path, replaceExisting: true, masterPasswordHash: PASSWORD },
  });
  assert.equal(restored.status, 200, await restored.clone().text());
  assert.equal((await restored.json()).imported.attachmentFiles, 1);
  await afterRestore();
  assert.equal(await blobExists(`${cipherId}/${attachmentId}`), true);

  const removed = await alice.request('/api/admin/backup/remote/file', { method: 'DELETE', json: { destinationId: DAV_ID, path, masterPasswordHash: PASSWORD } });
  assert.deepEqual(await removed.json(), { object: 'backup-remote-delete', deleted: true, path });
  assert.deepEqual(await remoteArchives(DAV_ID), []);
});

test('one run at a time', async () => {
  await db.query(`INSERT INTO job_leases (name, token, expires_at) VALUES ('backup', gen_random_uuid(), $1)`, [new Date(Date.now() + 60_000)]);
  try {
    const busy = await alice.request('/api/admin/backup/run', { method: 'POST', json: { destinationId: S3_ID, masterPasswordHash: PASSWORD } });
    assert.equal(busy.status, 409);
    assert.equal((await busy.json()).message, 'Another backup run is already in progress');
  } finally {
    await db.query(`DELETE FROM job_leases WHERE name = 'backup'`);
  }
});

test('the cron job catches up on a missed scheduled run', async () => {
  await saveSettings([s3Destination({ enabled: true, startTime: '00:00', intervalHours: 1 }), davDestination()]);
  // The latest hourly slot passed after the last run.
  await db.query(`UPDATE settings SET value = jsonb_set(value, '{destinations,${S3_ID},lastAttemptAt}', to_jsonb($1::text)) WHERE key = 'backup.runtime'`, [
    new Date(Date.now() - 2 * 3_600_000).toISOString(),
  ]);
  const before = (await alice.json('/api/admin/backup/settings')).destinations[0].runtime;

  const cron = await client.fetch('/api/internal/cron', { headers: { Authorization: 'Bearer test-cron-secret' } });
  assert.equal(cron.status, 200);
  const [s3] = (await alice.json('/api/admin/backup/settings')).destinations;
  assert.notEqual(s3.runtime.lastSuccessAt, before.lastSuccessAt);
  const logs = await alice.json('/api/admin/logs');
  assert.ok((logs.data ?? logs).some((entry: any) => entry.action === 'admin.backup.remote.scheduled'));

  // Nothing is due right after.
  await client.fetch('/api/internal/cron', { headers: { Authorization: 'Bearer test-cron-secret' } });
  const after = (await alice.json('/api/admin/backup/settings')).destinations[0].runtime;
  assert.equal(after.lastAttemptAt, s3.runtime.lastAttemptAt);
});
