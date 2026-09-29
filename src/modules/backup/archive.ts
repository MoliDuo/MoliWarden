import { createHash } from 'node:crypto';
import { unzipSync, zipSync, type UnzipFileInfo } from 'fflate';
import { APP_VERSION } from '../../../shared/app-version';
import { badRequest } from '../../http/errors';

// An instance backup is a zip of:
//   manifest.json                     what is inside
//   db.json                           the rows of the tables below
//   attachments/<cipher>/<id>.bin     attachment files, when included
// Archives made for a remote destination leave the files out: they are
// stored next to the archive and listed in manifest.attachmentBlobs.
//
// Sessions, devices, Sends and other short-lived state are not backed up.

export const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 10_000;
const MAX_DB_JSON_BYTES = 32 * 1024 * 1024;
const CHECKSUM_LENGTH = 5;
// Wire name of the files; renamed with the 3.3 migration.
const FILE_PREFIX = 'nodewarden_backup_';
const ARCHIVE_NAME = /^(?:nodewarden|moliwarden)_backup_\d{8}_\d{6}(?:_[0-9a-f]{5})?\.zip$/i;

type Row = Record<string, unknown>;

// The tables, parents first, with the columns backed up and the values
// older archives may lack.
export const TABLES = {
  config: { columns: ['key', 'value'] },
  users: {
    columns: [
      'id', 'email', 'name', 'master_password_hint', 'master_password_hash', 'key', 'private_key', 'public_key',
      'kdf_type', 'kdf_iterations', 'kdf_memory', 'kdf_parallelism', 'security_stamp', 'role', 'status',
      'verify_devices', 'totp_secret', 'totp_recovery_code', 'yubikey_key1', 'yubikey_key2', 'yubikey_key3',
      'yubikey_key4', 'yubikey_key5', 'yubikey_nfc', 'created_at', 'updated_at',
    ],
    defaults: { role: 'user', status: 'active', verify_devices: 0, yubikey_nfc: 0 },
  },
  domain_settings: {
    columns: ['user_id', 'equivalent_domains', 'custom_equivalent_domains', 'excluded_global_equivalent_domains', 'updated_at'],
    defaults: { equivalent_domains: '[]', custom_equivalent_domains: '[]', excluded_global_equivalent_domains: '[]' },
  },
  user_revisions: { columns: ['user_id', 'revision_date'] },
  webauthn_credentials: {
    columns: [
      'id', 'user_id', 'purpose', 'name', 'public_key', 'credential_id', 'counter', 'type', 'aa_guid', 'transports',
      'encrypted_user_key', 'encrypted_public_key', 'encrypted_private_key', 'supports_prf', 'slot', 'created_at', 'updated_at',
    ],
    defaults: { purpose: 'login', counter: 0, supports_prf: 0 },
  },
  folders: { columns: ['id', 'user_id', 'name', 'created_at', 'updated_at'] },
  organizations: { columns: ['id', 'name', 'billing_email', 'public_key', 'private_key', 'created_at', 'updated_at'] },
  org_memberships: {
    columns: ['id', 'org_id', 'user_id', 'status', 'type', 'access_all', 'akey', 'revoked_status', 'invited_by', 'created_at', 'updated_at'],
    defaults: { access_all: 0 },
  },
  collections: { columns: ['id', 'org_id', 'name', 'external_id', 'created_at', 'updated_at'] },
  collection_members: {
    columns: ['collection_id', 'membership_id', 'read_only', 'hide_passwords', 'manage'],
    defaults: { read_only: 0, hide_passwords: 0, manage: 0 },
  },
  ciphers: {
    columns: [
      'id', 'user_id', 'organization_id', 'type', 'folder_id', 'name', 'notes', 'favorite', 'data', 'reprompt', 'key',
      'created_at', 'updated_at', 'archived_at', 'deleted_at',
    ],
    defaults: { favorite: 0 },
  },
  cipher_collections: { columns: ['cipher_id', 'collection_id'] },
  cipher_user_state: { columns: ['cipher_id', 'user_id', 'folder_id', 'favorite', 'archived_at'], defaults: { favorite: 0 } },
  attachments: { columns: ['id', 'cipher_id', 'file_name', 'size', 'size_name', 'key'] },
} satisfies Record<string, { columns: string[]; defaults?: Row }>;

export type TableName = keyof typeof TABLES;
export type Snapshot = Record<TableName, Row[]>;
export const TABLE_NAMES = Object.keys(TABLES) as TableName[];
// Archives from before organizations have none of these.
const OPTIONAL_TABLES = new Set<TableName>([
  'domain_settings', 'webauthn_credentials', 'organizations', 'org_memberships', 'collections',
  'collection_members', 'cipher_collections', 'cipher_user_state',
]);

export interface AttachmentRef {
  cipherId: string;
  attachmentId: string;
  blobName: string;
  sizeBytes: number;
}

export interface Manifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: 's3';
  tableCounts: Record<string, number>;
  includes: { attachments: boolean };
  blobSummary: { attachmentFiles: number; totalBytes: number; largestObjectBytes: number };
  attachmentBlobs: AttachmentRef[];
}

export interface Archive {
  bytes: Uint8Array<ArrayBuffer>;
  fileName: string;
  manifest: Manifest;
}

export interface Integrity {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}

const SEGMENT = /^[A-Za-z0-9._-]{1,128}$/;
const isSegment = (value: unknown) => typeof value === 'string' && SEGMENT.test(value) && value !== '.' && value !== '..';

// "<cipherId>/<attachmentId>": the file's key in the blob store.
export function isBlobName(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const parts = value.split('/');
  return parts.length === 2 && parts.every(isSegment);
}

export const isArchiveName = (name: string) => ARCHIVE_NAME.test(name);
export const attachmentEntry = (cipherId: string, attachmentId: string) => `attachments/${cipherId}/${attachmentId}.bin`;

export function integrityOf(bytes: Uint8Array, fileName: string): Integrity {
  const expectedPrefix = /_([0-9a-f]{5})\.zip$/i.exec(fileName.trim())?.[1].toLowerCase() ?? null;
  const actualPrefix = createHash('sha256').update(bytes).digest('hex').slice(0, CHECKSUM_LENGTH);
  return { hasChecksumPrefix: !!expectedPrefix, expectedPrefix, actualPrefix, matches: !expectedPrefix || actualPrefix === expectedPrefix };
}

function stamp(date: Date, timeZone: string): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const pick = (type: string) => parts.find((part) => part.type === type)?.value ?? '';
  return `${pick('year')}${pick('month')}${pick('day')}_${pick('hour')}${pick('minute')}${pick('second')}`;
}

export function buildArchive(snapshot: Snapshot, options: { date: Date; timeZone: string; includeAttachments: boolean }): Archive {
  const attachments = options.includeAttachments ? snapshot.attachments : [];
  const refs: AttachmentRef[] = attachments.map((row) => ({
    cipherId: String(row.cipher_id),
    attachmentId: String(row.id),
    blobName: `${row.cipher_id}/${row.id}`,
    sizeBytes: Number(row.size) || 0,
  }));
  const db = { ...snapshot, attachments };
  const manifest: Manifest = {
    formatVersion: 1,
    exportedAt: options.date.toISOString(),
    appVersion: APP_VERSION,
    storageKind: 's3',
    tableCounts: Object.fromEntries(TABLE_NAMES.map((table) => [table, db[table].length])),
    includes: { attachments: options.includeAttachments },
    blobSummary: {
      attachmentFiles: refs.length,
      totalBytes: refs.reduce((sum, ref) => sum + ref.sizeBytes, 0),
      largestObjectBytes: refs.reduce((max, ref) => Math.max(max, ref.sizeBytes), 0),
    },
    attachmentBlobs: refs,
  };
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value, null, 2));
  // Stored, not deflated: the payload is mostly ciphertext.
  const bytes = zipSync({ 'manifest.json': encode(manifest), 'db.json': encode(db) }, { level: 0 });
  const checksum = integrityOf(bytes, '').actualPrefix;
  return { bytes, fileName: `${FILE_PREFIX}${stamp(options.date, options.timeZone)}_${checksum}.zip`, manifest };
}

export interface ParsedArchive {
  manifest: Manifest;
  snapshot: Snapshot;
  // Attachment files in the archive, by "<cipherId>/<attachmentId>".
  files: Map<string, Uint8Array<ArrayBuffer>>;
  // Where the files left out of the archive are, by the same key.
  external: Map<string, string>;
}

const invalid = (message: string) => badRequest(`Invalid backup: ${message}`);

function unzip(bytes: Uint8Array<ArrayBuffer>): Record<string, Uint8Array<ArrayBuffer>> {
  let entries = 0;
  let expanded = 0;
  const filter = (file: UnzipFileInfo) => {
    if (++entries > MAX_ENTRIES) throw invalid('the archive has too many files');
    const name = file.name;
    const attachment = /^attachments\/([^/]+)\/([^/]+)\.bin$/.exec(name);
    if (name !== 'manifest.json' && name !== 'db.json' && !(attachment && isSegment(attachment[1]) && isSegment(attachment[2]))) {
      throw invalid(`unexpected file ${name.slice(0, 200)}`);
    }
    if (name === 'db.json' && file.originalSize > MAX_DB_JSON_BYTES) throw invalid('db.json is too large');
    expanded += file.originalSize;
    if (expanded > MAX_ARCHIVE_BYTES) throw invalid('the archive expands beyond the restore limit');
    return true;
  };
  try {
    return unzipSync(bytes, { filter }) as Record<string, Uint8Array<ArrayBuffer>>;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Invalid backup')) throw error;
    throw invalid('not a zip archive');
  }
}

function json(bytes: Uint8Array | undefined, name: string): unknown {
  if (!bytes) throw invalid(`${name} is missing`);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw invalid(`${name} is not valid JSON`);
  }
}

// Every column holds text, a number or a 0/1 flag.
function cell(table: string, value: unknown): string | number | null {
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (value === null || typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value))) return value;
  throw invalid(`table ${table} has a malformed value`);
}

function snapshotOf(value: unknown): Snapshot {
  if (!value || typeof value !== 'object') throw invalid('db.json is not an object');
  const source = value as Record<string, unknown>;
  const snapshot = {} as Snapshot;
  for (const table of TABLE_NAMES) {
    const rows = source[table] ?? (OPTIONAL_TABLES.has(table) ? [] : undefined);
    if (!Array.isArray(rows) || rows.some((row) => !row || typeof row !== 'object')) throw invalid(`table ${table} is missing or malformed`);
    const { columns, defaults = {} } = TABLES[table] as { columns: string[]; defaults?: Row };
    snapshot[table] = rows.map((row: Row) => Object.fromEntries(columns.map((column) => [column, cell(table, row[column] ?? defaults[column] ?? null)])));
  }
  // What the database does not check itself.
  for (const cipher of snapshot.ciphers) {
    if (!isSegment(cipher.id) || !cipher.user_id === !cipher.organization_id) throw invalid('a cipher has no single owner');
  }
  for (const attachment of snapshot.attachments) {
    if (!isSegment(attachment.id) || !isSegment(attachment.cipher_id)) throw invalid('an attachment has a malformed id');
  }
  for (const passkey of snapshot.webauthn_credentials) {
    if (passkey.purpose !== 'login' && passkey.purpose !== 'twoFactor') throw invalid('a passkey has an unknown purpose');
  }
  return snapshot;
}

export function readArchive(bytes: Uint8Array<ArrayBuffer>): ParsedArchive {
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) {
    throw badRequest(`Backup archive is too large. The restore limit is ${MAX_ARCHIVE_BYTES / 1024 / 1024} MiB`);
  }
  const entries = unzip(bytes);
  const manifest = json(entries['manifest.json'], 'manifest.json') as Manifest;
  if (manifest?.formatVersion !== 1) throw badRequest('Unsupported backup format version');
  const snapshot = snapshotOf(json(entries['db.json'], 'db.json'));

  const files = new Map<string, Uint8Array<ArrayBuffer>>();
  const external = new Map<string, string>();
  const refs = new Map((Array.isArray(manifest.attachmentBlobs) ? manifest.attachmentBlobs : []).map((ref) => [`${ref.cipherId}/${ref.attachmentId}`, ref.blobName]));
  for (const attachment of snapshot.attachments) {
    const key = `${attachment.cipher_id}/${attachment.id}`;
    const inline = entries[attachmentEntry(String(attachment.cipher_id), String(attachment.id))];
    const blobName = refs.get(key);
    if (inline) files.set(key, inline);
    else if (isBlobName(blobName)) external.set(key, blobName);
    else throw invalid(`the file of attachment ${key} is missing`);
  }
  return { manifest, snapshot, files, external };
}
