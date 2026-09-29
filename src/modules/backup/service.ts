import type { Caller } from '../../http/authenticate';
import { badRequest, conflict, HttpError, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { withLease } from '../../platform/db/lease';
import { recordAudit, requestMetadata } from '../audit/service';
import { requireMasterPassword } from '../auth/password';
import { verifyUserVerification } from '../auth/user-verification';
import { integrityOf, isBlobName, readArchive, type Archive } from './archive';
import { readStoredSettings } from './repo';
import { normalizePath, parentOf } from './remote';
import { restoreArchive } from './restore';
import { BACKUP_LEASE, BACKUP_LEASE_MS, openStore, remoteAttachmentPath, runNow } from './runs';
import type { BackupFileBody, ImportForm, RemoteFileBody, RemoteRestoreBody, RepairBody, RunBody, SettingsBody } from './schemas';
import { defaultSettings, findDestination, missingSetting, redacted, settingsFrom, type Settings } from './settings';
import { openSettings, portableSettings } from './settings-crypto';
import { createArchive, destinationSummary, loadSettings, saveSettings } from './state';

// Instance backups, for admins: download or restore an archive of every
// account and vault, and keep copies on S3 or WebDAV destinations.

const audit = (deps: Deps, caller: Caller | null, action: string, metadata: Record<string, unknown>) =>
  recordAudit(deps.db, {
    actorUserId: caller?.user.id ?? null,
    action,
    category: 'data',
    level: action.endsWith('.failed') ? 'error' : 'info',
    targetType: 'backup',
    metadata: { ...metadata, ...(caller ? requestMetadata(caller.request) : {}) },
  });

const scheduledCount = (settings: Settings) => settings.destinations.filter((entry) => entry.schedule.enabled).length;

// Settings -------------------------------------------------------------------

export async function settingsJson(deps: Deps): Promise<Settings> {
  return redacted(await loadSettings(deps));
}

// Settings from another server are replaced by what the admin sends.
const currentOrDefault = (deps: Deps) =>
  loadSettings(deps).catch((error: unknown) => {
    if (error instanceof HttpError && error.status === 409) return defaultSettings();
    throw error;
  });

async function save(deps: Deps, caller: Caller, action: string, input: SettingsBody): Promise<Settings> {
  const next = settingsFrom(input, await currentOrDefault(deps), deps.config.backupAllowPrivateHosts);
  await saveSettings(deps, next);
  await audit(deps, caller, action, { destinationCount: next.destinations.length, scheduledDestinationCount: scheduledCount(next) });
  return redacted(next);
}

export async function updateSettings(deps: Deps, caller: Caller, input: SettingsBody): Promise<Settings> {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  return save(deps, caller, 'admin.backup.settings.update', input);
}

// Whether the settings came from another server, and the copy an admin's
// client can decrypt to repair them.
export async function repairState(deps: Deps) {
  const raw = await readStoredSettings(deps.db);
  const needsRepair = !!raw && openSettings(raw, deps.config.jwtSecret) === null;
  return { object: 'backup-settings-repair', needsRepair, portable: needsRepair ? portableSettings(raw!) : null };
}

// Admins who signed in with a passkey have no master password to confirm
// with; the client proves a fresh verification instead.
export async function repairSettings(deps: Deps, caller: Caller, input: RepairBody): Promise<Settings> {
  if (input.masterPasswordHash?.trim()) {
    await requireMasterPassword(caller.user, input.masterPasswordHash);
  } else if (!input.userVerificationToken?.trim()) {
    throw badRequest('masterPasswordHash or userVerificationToken is required');
  } else if (!verifyUserVerification(deps.tokens, input.userVerificationToken, caller.user, 'backup.settings.repair')) {
    throw badRequest('Invalid user verification token');
  }
  return save(deps, caller, 'admin.backup.settings.repair', input);
}

// Local archives ---------------------------------------------------------------

// The archive holds the attachments' rows; the client fetches their files
// one by one (attachmentFile) and adds them.
export async function exportArchive(deps: Deps, caller: Caller, input: BackupFileBody & { includeAttachments: boolean }): Promise<Archive> {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const archive = await createArchive(deps, new Date(), 'UTC', input.includeAttachments);
  await audit(deps, caller, 'admin.backup.export', {
    users: archive.manifest.counts.users,
    ciphers: archive.manifest.counts.ciphers,
    attachments: archive.manifest.counts.attachments,
    compressedBytes: archive.bytes.byteLength,
    includesAttachments: archive.manifest.includes.attachments,
  });
  return archive;
}

export async function attachmentFile(deps: Deps, caller: Caller, input: BackupFileBody & { blobName: string }) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const blobName = input.blobName.trim();
  if (!blobName) throw badRequest('Backup attachment blob is required');
  if (!isBlobName(blobName)) throw badRequest('Backup attachment blob is invalid');
  const object = await deps.blobs.get(blobName);
  if (!object) throw notFound('Backup attachment blob not found');
  return object;
}

function checkIntegrity(bytes: Uint8Array, fileName: string, allowMismatch: boolean): boolean {
  const { matches } = integrityOf(bytes, fileName);
  if (!matches && !allowMismatch) throw badRequest('Backup file checksum does not match its filename');
  return !matches;
}

const restoreMetadata = (result: Awaited<ReturnType<typeof restoreArchive>>['result'], replaceExisting: boolean) => ({
  users: result.imported.users,
  ciphers: result.imported.ciphers,
  attachments: result.imported.attachmentFiles,
  skippedAttachments: result.skipped.attachments,
  skippedReason: result.skipped.reason,
  replaceExisting,
});

// Held for the whole restore, so no backup run reads a half-restored server.
async function exclusively<T>(deps: Deps, job: () => Promise<T>): Promise<T> {
  const outcome = await withLease(deps.db, BACKUP_LEASE, BACKUP_LEASE_MS, job);
  if (!outcome) throw conflict('Another backup or restore run is already in progress');
  return outcome.value;
}

export async function importArchive(deps: Deps, caller: Caller, input: ImportForm) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const mismatchAccepted = checkIntegrity(input.bytes, input.fileName, input.allowChecksumMismatch);
  const archive = readArchive(input.bytes);
  const { result, actorUserId } = await exclusively(deps, () =>
    restoreArchive(deps, caller, archive, { replaceExisting: input.replaceExisting, fetchExternal: null }),
  );
  await recordAudit(deps.db, {
    actorUserId,
    action: 'admin.backup.import',
    category: 'data',
    targetType: 'backup',
    metadata: {
      ...restoreMetadata(result, input.replaceExisting),
      trigger: 'local',
      bytes: input.bytes.byteLength,
      checksumMismatchAccepted: mismatchAccepted,
      ...requestMetadata(caller.request),
    },
  });
  return result;
}

// Destinations -----------------------------------------------------------------

export async function runBackup(deps: Deps, caller: Caller, input: RunBody) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const destination = findDestination(await loadSettings(deps), input.destinationId);
  const missing = missingSetting(destination);
  if (missing) throw badRequest(missing);
  const result = await runNow(deps, destination, { userId: caller.user.id, metadata: requestMetadata(caller.request) });
  if (!result) throw conflict('Another backup run is already in progress');
  return { object: 'backup-run', result, settings: await settingsJson(deps) };
}

async function openDestination(deps: Deps, destinationId: string | null) {
  const destination = findDestination(await loadSettings(deps), destinationId);
  return { destination, store: openStore(deps, destination) };
}

export async function listRemote(deps: Deps, destinationId: string | null, path: string) {
  const { destination, store } = await openDestination(deps, destinationId);
  const currentPath = normalizePath(path);
  const items = (await store.list(currentPath)).sort(
    (a, b) => Number(b.isDirectory) - Number(a.isDirectory) || b.name.localeCompare(a.name, 'en'),
  );
  return {
    object: 'backup-remote-browser',
    destinationId: destination.id,
    destinationName: destination.name,
    provider: destination.type,
    currentPath,
    parentPath: parentOf(currentPath),
    items,
  };
}

function archivePath(path: string): string {
  const normalized = normalizePath(path);
  if (!/\.zip$/i.test(normalized)) throw badRequest('Please select a backup ZIP file');
  return normalized;
}

const fileNameOf = (path: string) => path.split('/').pop()!;

async function readRemote(deps: Deps, caller: Caller, input: RemoteFileBody) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const path = archivePath(input.path);
  const { destination, store } = await openDestination(deps, input.destinationId);
  const bytes = await store.get(path);
  if (!bytes) throw notFound('Remote backup file not found');
  return { destination, store, path, fileName: fileNameOf(path), bytes };
}

export async function downloadRemote(deps: Deps, caller: Caller, input: RemoteFileBody) {
  const { fileName, bytes } = await readRemote(deps, caller, input);
  return { fileName, bytes };
}

export async function inspectRemote(deps: Deps, caller: Caller, input: RemoteFileBody) {
  const { destination, path, fileName, bytes } = await readRemote(deps, caller, input);
  return { object: 'backup-remote-integrity', destinationId: destination.id, path, fileName, integrity: integrityOf(bytes, fileName) };
}

export async function deleteRemote(deps: Deps, caller: Caller, input: RemoteFileBody) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const path = archivePath(input.path);
  const { destination, store } = await openDestination(deps, input.destinationId);
  await store.delete(path);
  await audit(deps, caller, 'admin.backup.remote.delete', { ...destinationSummary(destination), remotePath: path });
  return { object: 'backup-remote-delete', deleted: true, path };
}

// Restores an archive from a destination, with the attachment files stored
// next to it.
export async function restoreRemote(deps: Deps, caller: Caller, input: RemoteRestoreBody) {
  const { destination, store, path, fileName, bytes } = await readRemote(deps, caller, input);
  const mismatchAccepted = checkIntegrity(bytes, fileName, input.allowChecksumMismatch);
  const archive = readArchive(bytes);
  const { result, actorUserId } = await exclusively(deps, () =>
    restoreArchive(deps, caller, archive, {
      replaceExisting: input.replaceExisting,
      fetchExternal: (blobName) => store.get(remoteAttachmentPath(blobName)),
    }),
  );
  await recordAudit(deps.db, {
    actorUserId,
    action: 'admin.backup.import',
    category: 'data',
    targetType: 'backup',
    metadata: {
      ...restoreMetadata(result, input.replaceExisting),
      ...destinationSummary(destination),
      remotePath: path,
      trigger: 'remote',
      bytes: bytes.byteLength,
      checksumMismatchAccepted: mismatchAccepted,
      ...requestMetadata(caller.request),
    },
  });
  return result;
}
