import { createHash } from 'node:crypto';
import { unzipSync, zipSync, type UnzipFileInfo } from 'fflate';
import { APP_VERSION } from '../../../shared/app-version';
import { badRequest } from '../../http/errors';
import type { Database } from '../../platform/db/schema';

// An instance backup is a zip of:
//   manifest.json                     what is inside
//   vault.json                        the records below, by kind
//   attachments/<cipher>/<id>.bin     attachment files, when included
// Archives made for a remote destination leave the files out: they are
// stored next to the archive and listed in manifest.attachmentBlobs.
//
// The records describe accounts and vaults, not tables: each kind lists its
// fields, and a field is stored in the column of the same name in
// snake_case. Sessions, devices, Sends and other short-lived state are not
// backed up.

export const FORMAT_VERSION = 2;
export const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 10_000;
const MAX_VAULT_JSON_BYTES = 32 * 1024 * 1024;
const CHECKSUM_LENGTH = 5;
const FILE_PREFIX = 'moliwarden_backup_';
const ARCHIVE_NAME = /^moliwarden_backup_\d{8}_\d{6}(?:_[0-9a-f]{5})?\.zip$/i;

type FieldType = 'text' | 'int' | 'bool' | 'time' | 'json' | 'object' | 'ints' | 'texts';
type RecordValue = string | number | boolean | unknown[] | Record<string, unknown> | null;
export type VaultRecord = Record<string, RecordValue>;

interface RecordKind {
  table: keyof Database;
  fields: Record<string, FieldType>;
  // Records in a stable order, so the same data gives the same archive.
  order: string[];
}

const BY_CREATION = ['createdAt', 'id'];

// Parents first: that is the order they are restored in.
export const RECORD_KINDS = {
  // Server settings worth carrying over; see BACKED_UP_SETTINGS.
  settings: { table: 'settings', fields: { key: 'text', value: 'json' }, order: ['key'] },
  users: {
    table: 'users',
    fields: {
      id: 'text', email: 'text', name: 'text', masterPasswordHash: 'text', masterPasswordHint: 'text', key: 'text',
      keyId: 'text', publicKey: 'text', privateKey: 'text', kdfType: 'int', kdfIterations: 'int', kdfMemory: 'int',
      kdfParallelism: 'int', securityStamp: 'text', role: 'text', status: 'text', verifyDevices: 'bool',
      recoveryCode: 'text', customDomains: 'json', excludedGlobalDomains: 'ints', revisionDate: 'time',
      createdAt: 'time', updatedAt: 'time',
    },
    order: BY_CREATION,
  },
  twoFactorProviders: {
    table: 'two_factor_providers',
    fields: { userId: 'text', type: 'int', data: 'object' },
    order: ['userId', 'type'],
  },
  passkeys: {
    table: 'webauthn_credentials',
    fields: {
      id: 'text', userId: 'text', purpose: 'text', slot: 'int', name: 'text', credentialId: 'text', publicKey: 'text',
      counter: 'int', type: 'text', aaGuid: 'text', transports: 'texts', supportsPrf: 'bool', encryptedUserKey: 'text',
      encryptedPublicKey: 'text', encryptedPrivateKey: 'text', createdAt: 'time', updatedAt: 'time',
    },
    order: BY_CREATION,
  },
  folders: {
    table: 'folders',
    fields: { id: 'text', userId: 'text', name: 'text', createdAt: 'time', updatedAt: 'time' },
    order: BY_CREATION,
  },
  organizations: {
    table: 'organizations',
    fields: {
      id: 'text', name: 'text', billingEmail: 'text', publicKey: 'text', privateKey: 'text', createdAt: 'time', updatedAt: 'time',
    },
    order: BY_CREATION,
  },
  memberships: {
    table: 'memberships',
    fields: {
      id: 'text', organizationId: 'text', userId: 'text', status: 'int', type: 'int', accessAll: 'bool', key: 'text',
      revokedStatus: 'int', invitedBy: 'text', createdAt: 'time', updatedAt: 'time',
    },
    order: BY_CREATION,
  },
  collections: {
    table: 'collections',
    fields: { id: 'text', organizationId: 'text', name: 'text', externalId: 'text', createdAt: 'time', updatedAt: 'time' },
    order: BY_CREATION,
  },
  collectionGrants: {
    table: 'collection_grants',
    fields: { collectionId: 'text', membershipId: 'text', readOnly: 'bool', hidePasswords: 'bool', manage: 'bool' },
    order: ['collectionId', 'membershipId'],
  },
  ciphers: {
    table: 'ciphers',
    fields: {
      id: 'text', userId: 'text', organizationId: 'text', type: 'int', key: 'text', reprompt: 'int', data: 'object',
      createdAt: 'time', updatedAt: 'time', deletedAt: 'time',
    },
    order: BY_CREATION,
  },
  cipherCollections: {
    table: 'cipher_collections',
    fields: { cipherId: 'text', collectionId: 'text' },
    order: ['cipherId', 'collectionId'],
  },
  cipherStates: {
    table: 'cipher_user_state',
    fields: { cipherId: 'text', userId: 'text', folderId: 'text', favorite: 'bool', archivedAt: 'time' },
    order: ['cipherId', 'userId'],
  },
  // Only attachments whose file was uploaded.
  attachments: {
    table: 'attachments',
    fields: { id: 'text', cipherId: 'text', fileName: 'text', key: 'text', size: 'int', uploadedAt: 'time', createdAt: 'time' },
    order: ['cipherId', 'id'],
  },
} as const satisfies Record<string, RecordKind>;

export type KindName = keyof typeof RECORD_KINDS;
export type Snapshot = Record<KindName, VaultRecord[]>;
export const KIND_NAMES = Object.keys(RECORD_KINDS) as KindName[];

export const columnOf = (field: string) => field.replace(/[A-Z]/g, (char) => `_${char.toLowerCase()}`);

export interface AttachmentRef {
  cipherId: string;
  attachmentId: string;
  blobName: string;
  sizeBytes: number;
}

export interface Manifest {
  formatVersion: typeof FORMAT_VERSION;
  exportedAt: string;
  appVersion: string;
  counts: Record<KindName, number>;
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
  const refs: AttachmentRef[] = attachments.map((record) => ({
    cipherId: String(record.cipherId),
    attachmentId: String(record.id),
    blobName: `${record.cipherId}/${record.id}`,
    sizeBytes: Number(record.size) || 0,
  }));
  const vault = { ...snapshot, attachments };
  const manifest: Manifest = {
    formatVersion: FORMAT_VERSION,
    exportedAt: options.date.toISOString(),
    appVersion: APP_VERSION,
    counts: Object.fromEntries(KIND_NAMES.map((kind) => [kind, vault[kind].length])) as Record<KindName, number>,
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
  const bytes = zipSync({ 'manifest.json': encode(manifest), 'vault.json': encode(vault) }, { level: 0 });
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
const OLD_FORMAT =
  'the archive is in the format of an earlier version. Convert it with `npm run backup:convert-v1` (see the README), then import the result.';

function unzip(bytes: Uint8Array<ArrayBuffer>): Record<string, Uint8Array<ArrayBuffer>> {
  let entries = 0;
  let expanded = 0;
  const filter = (file: UnzipFileInfo) => {
    if (++entries > MAX_ENTRIES) throw invalid('the archive has too many files');
    const name = file.name;
    const attachment = /^attachments\/([^/]+)\/([^/]+)\.bin$/.exec(name);
    if (name === 'db.json') throw invalid(OLD_FORMAT);
    if (name !== 'manifest.json' && name !== 'vault.json' && !(attachment && isSegment(attachment[1]) && isSegment(attachment[2]))) {
      throw invalid(`unexpected file ${name.slice(0, 200)}`);
    }
    if (name === 'vault.json' && file.originalSize > MAX_VAULT_JSON_BYTES) throw invalid('vault.json is too large');
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

const isTime = (value: unknown) => typeof value === 'string' && !Number.isNaN(Date.parse(value));

const CHECKS: Record<FieldType, (value: unknown) => boolean> = {
  text: (value) => typeof value === 'string',
  int: (value) => Number.isSafeInteger(value),
  bool: (value) => typeof value === 'boolean',
  time: isTime,
  json: () => true,
  object: (value) => typeof value === 'object' && !Array.isArray(value),
  ints: (value) => Array.isArray(value) && value.every((item) => Number.isSafeInteger(item)),
  texts: (value) => Array.isArray(value) && value.every((item) => typeof item === 'string'),
};

// Each record has exactly the fields of its kind; a missing one is null.
// The database checks the rest (required fields, ranges, references).
function snapshotOf(value: unknown): Snapshot {
  if (!value || typeof value !== 'object') throw invalid('vault.json is not an object');
  const source = value as Record<string, unknown>;
  const snapshot = {} as Snapshot;
  for (const kind of KIND_NAMES) {
    const records = source[kind];
    if (!Array.isArray(records) || records.some((record) => !record || typeof record !== 'object')) {
      throw invalid(`${kind} is missing or malformed`);
    }
    const fields = Object.entries(RECORD_KINDS[kind].fields) as Array<[string, FieldType]>;
    snapshot[kind] = records.map((record: Record<string, unknown>) =>
      Object.fromEntries(
        fields.map(([field, type]) => {
          const cell = record[field] ?? null;
          if (cell !== null && !CHECKS[type](cell)) throw invalid(`${kind} has a malformed ${field}`);
          return [field, cell as RecordValue];
        }),
      ),
    );
  }
  // Ids that become blob paths.
  for (const attachment of snapshot.attachments) {
    if (!isSegment(attachment.id) || !isSegment(attachment.cipherId)) throw invalid('an attachment has a malformed id');
  }
  return snapshot;
}

export function readArchive(bytes: Uint8Array<ArrayBuffer>): ParsedArchive {
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) {
    throw badRequest(`Backup archive is too large. The restore limit is ${MAX_ARCHIVE_BYTES / 1024 / 1024} MiB`);
  }
  const entries = unzip(bytes);
  const manifest = json(entries['manifest.json'], 'manifest.json') as Manifest;
  if ((manifest?.formatVersion as number) === 1) throw invalid(OLD_FORMAT);
  if (manifest?.formatVersion !== FORMAT_VERSION) throw badRequest('Unsupported backup format version');
  const snapshot = snapshotOf(json(entries['vault.json'], 'vault.json'));

  const files = new Map<string, Uint8Array<ArrayBuffer>>();
  const external = new Map<string, string>();
  const refs = new Map((Array.isArray(manifest.attachmentBlobs) ? manifest.attachmentBlobs : []).map((ref) => [`${ref.cipherId}/${ref.attachmentId}`, ref.blobName]));
  for (const attachment of snapshot.attachments) {
    const key = `${attachment.cipherId}/${attachment.id}`;
    const inline = entries[attachmentEntry(String(attachment.cipherId), String(attachment.id))];
    const blobName = refs.get(key);
    if (inline) files.set(key, inline);
    else if (isBlobName(blobName)) external.set(key, blobName);
    else throw invalid(`the file of attachment ${key} is missing`);
  }
  return { manifest, snapshot, files, external };
}
