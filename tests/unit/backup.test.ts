import { test } from 'node:test';
import assert from 'node:assert/strict';
import { zipSync } from 'fflate';
import { buildArchive, integrityOf, isArchiveName, isBlobName, KIND_NAMES, readArchive, type Snapshot } from '../../src/modules/backup/archive';
import { checkEndpointUrl } from '../../src/modules/backup/endpoint';
import { isDue, latestSlot } from '../../src/modules/backup/schedule';
import { emptyRuntime } from '../../src/modules/backup/settings';

const schedule = (overrides: Partial<Parameters<typeof isDue>[0]> = {}) => ({
  enabled: true,
  intervalHours: 24,
  startTime: '03:00',
  timezone: 'UTC',
  retentionCount: 30,
  ...overrides,
});

test('latestSlot is the last passed slot, from yesterday before the first one', () => {
  assert.equal(latestSlot(schedule(), new Date('2026-05-04T10:00:00Z')).toISOString(), '2026-05-04T03:00:00.000Z');
  assert.equal(latestSlot(schedule(), new Date('2026-05-04T02:00:00Z')).toISOString(), '2026-05-03T03:00:00.000Z');
  assert.equal(
    latestSlot(schedule({ intervalHours: 6 }), new Date('2026-05-04T16:00:00Z')).toISOString(),
    '2026-05-04T15:00:00.000Z',
  );
  // In the destination's time zone: 03:00 in Shanghai is 19:00 UTC the day before.
  assert.equal(
    latestSlot(schedule({ timezone: 'Asia/Shanghai' }), new Date('2026-05-04T10:00:00Z')).toISOString(),
    '2026-05-03T19:00:00.000Z',
  );
});

test('isDue catches up once per missed slot', () => {
  const now = new Date('2026-05-04T10:00:00Z');
  assert.equal(isDue(schedule(), emptyRuntime(), now), true);
  assert.equal(isDue(schedule({ enabled: false }), emptyRuntime(), now), false);
  assert.equal(isDue(schedule(), { ...emptyRuntime(), lastAttemptAt: '2026-05-04T03:05:00Z' }, now), false);
  assert.equal(isDue(schedule(), { ...emptyRuntime(), lastAttemptAt: '2026-05-03T03:05:00Z' }, now), true);
  // Every two days: not while the last success is recent.
  const twoDays = schedule({ intervalHours: 48 });
  const recent = { ...emptyRuntime(), lastAttemptAt: '2026-05-03T03:00:00Z', lastSuccessAt: '2026-05-03T03:00:00Z' };
  assert.equal(isDue(twoDays, recent, now), false);
  assert.equal(isDue(twoDays, recent, new Date('2026-05-05T03:30:00Z')), true);
});

test('destinations must be public http(s) URLs', () => {
  for (const url of ['http://127.0.0.1', 'http://169.254.169.254', 'http://[::1]', 'http://[::ffff:10.0.0.1]', 'http://[fc00::1]', 'http://localhost:8080', 'http://nas.local']) {
    assert.throws(() => checkEndpointUrl(url, 'WebDAV server URL', false), /host is not allowed/, url);
  }
  // Public addresses, among them Cloudflare R2's.
  for (const url of ['https://1.1.1.1', 'https://172.64.66.1', 'https://[2606:4700:113::1]', 'https://[::ffff:8.8.8.8]']) {
    assert.equal(checkEndpointUrl(url, 'S3 endpoint', false), new URL(url).toString().replace(/\/$/, ''), url);
  }
  assert.throws(() => checkEndpointUrl('ftp://example.com', 'S3 endpoint', false), /must start with http/);
  assert.throws(() => checkEndpointUrl('https://user:pw@example.com', 'S3 endpoint', false), /credentials/);
  assert.equal(checkEndpointUrl('https://dav.example.com/remote.php/', 'WebDAV server URL', false), 'https://dav.example.com/remote.php');
  assert.equal(checkEndpointUrl('http://127.0.0.1:9000', 'S3 endpoint', true), 'http://127.0.0.1:9000');
});

function snapshot(): Snapshot {
  const empty = Object.fromEntries(KIND_NAMES.map((kind) => [kind, []])) as unknown as Snapshot;
  const now = '2026-05-04T00:00:00.000Z';
  return {
    ...empty,
    users: [{ id: 'u1', email: 'a@example.com', masterPasswordHash: '$s$x', key: 'k', kdfType: 0, kdfIterations: 600000, securityStamp: 's', createdAt: now, updatedAt: now }],
    ciphers: [{ id: 'c1', userId: 'u1', organizationId: null, type: 1, data: { name: 'n' }, createdAt: now, updatedAt: now }],
    attachments: [{ id: 'a1', cipherId: 'c1', fileName: 'f', size: 3, key: null, uploadedAt: now, createdAt: now }],
  };
}

test('archives round-trip and name their checksum', () => {
  const archive = buildArchive(snapshot(), { date: new Date('2026-05-04T01:02:03Z'), timeZone: 'Asia/Shanghai', includeAttachments: true });
  assert.match(archive.fileName, /^moliwarden_backup_20260504_090203_[0-9a-f]{5}\.zip$/);
  assert.ok(isArchiveName(archive.fileName));
  assert.equal(integrityOf(archive.bytes, archive.fileName).matches, true);
  assert.equal(integrityOf(archive.bytes, archive.fileName.replace(/_[0-9a-f]{5}\.zip/, '_00000.zip')).matches, false);

  const parsed = readArchive(archive.bytes);
  // Fields a record leaves out read as null; unknown ones are dropped.
  assert.equal(parsed.snapshot.users[0].verifyDevices, null);
  assert.deepEqual(parsed.snapshot.ciphers[0].data, { name: 'n' });
  assert.equal(parsed.external.get('c1/a1'), 'c1/a1');
  assert.equal(parsed.files.size, 0);

  const without = readArchive(buildArchive(snapshot(), { date: new Date(), timeZone: 'UTC', includeAttachments: false }).bytes);
  assert.equal(without.snapshot.attachments.length, 0);
});

test('archives with unexpected content are refused', () => {
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  const manifest = { formatVersion: 2, attachmentBlobs: [] };
  const zip = (files: Record<string, Uint8Array>) => zipSync(files) as Uint8Array<ArrayBuffer>;
  assert.throws(() => readArchive(zip({ 'manifest.json': encode(manifest), 'vault.json': encode(snapshot()), '../evil': new Uint8Array(1) })), /unexpected file/);
  assert.throws(() => readArchive(zip({ 'manifest.json': encode({ formatVersion: 9 }), 'vault.json': encode(snapshot()) })), /Unsupported backup format/);
  // Archives of the earlier format point to the converter.
  assert.throws(() => readArchive(zip({ 'manifest.json': encode({ formatVersion: 1 }), 'db.json': encode({}) })), /backup:convert-v1/);
  // An attachment without its file.
  assert.throws(() => readArchive(zip({ 'manifest.json': encode(manifest), 'vault.json': encode(snapshot()) })), /file of attachment c1\/a1 is missing/);
  const nested = snapshot();
  nested.users[0].name = { evil: true };
  nested.attachments = [];
  assert.throws(() => readArchive(zip({ 'manifest.json': encode(manifest), 'vault.json': encode(nested) })), /users has a malformed name/);
  const missing = snapshot() as Partial<Snapshot>;
  delete missing.folders;
  assert.throws(() => readArchive(zip({ 'manifest.json': encode(manifest), 'vault.json': encode(missing) })), /folders is missing/);

  assert.equal(isBlobName('c1/a1'), true);
  for (const name of ['c1', '../a1', 'c1/..', 'sends/s/f', 'c1/a 1']) assert.equal(isBlobName(name), false, name);
});
