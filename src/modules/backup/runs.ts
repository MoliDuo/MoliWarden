import type { Deps } from '../../main/deps';
import { attachmentKey } from '../../platform/blob';
import { withLease } from '../../platform/db/lease';
import { recordAudit } from '../audit/service';
import { integrityOf, isArchiveName, type Archive, type AttachmentRef } from './archive';
import { createRemoteFetch, RemoteError } from './endpoint';
import { openRemoteStore, type RemoteStore } from './remote';
import { isDue } from './schedule';
import { missingSetting, type Destination } from './settings';
import { updateRuntime } from './repo';
import { createArchive, destinationSummary, loadSettings } from './state';

// A run uploads a fresh archive to a destination, then removes the oldest
// ones beyond its retention count. Attachment files go next to the
// archives, under attachments/, and only when they changed: an index file
// there records what was uploaded.
//
// Runs and restores hold the "backup" lease, so only one happens at a time
// across all function instances.

export const BACKUP_LEASE = 'backup';
export const BACKUP_LEASE_MS = 15 * 60 * 1000;
const UPLOAD_ATTEMPTS = 3;
const FILE_CONCURRENCY = 4;
// Wire name of the index; renamed with the 3.3 migration.
const INDEX_PATH = 'attachments/.moliwarden-attachment-index.v1.json';

export type Trigger = 'manual' | 'scheduled';

export interface RunResult {
  fileName: string;
  fileSize: number;
  provider: Destination['type'];
  remotePath: string;
}

export const openStore = (deps: Deps, destination: Destination): RemoteStore =>
  openRemoteStore(destination, createRemoteFetch(deps.config.backupAllowPrivateHosts), deps.config.backupAllowPrivateHosts);

export const remoteAttachmentPath = (blobName: string) => `attachments/${blobName}`;

async function readIndex(store: RemoteStore): Promise<Map<string, number>> {
  const bytes = await store.get(INDEX_PATH);
  try {
    const index = JSON.parse(new TextDecoder().decode(bytes ?? new Uint8Array())) as { blobs?: Record<string, { sizeBytes?: number }> };
    return new Map(Object.entries(index.blobs ?? {}).map(([name, entry]) => [name, Number(entry?.sizeBytes)]));
  } catch {
    // No index yet, or an unreadable one: everything is uploaded again.
    return new Map();
  }
}

async function writeIndex(store: RemoteStore, index: Map<string, number>): Promise<void> {
  const updatedAt = new Date().toISOString();
  const blobs = Object.fromEntries([...index].map(([name, sizeBytes]) => [name, { sizeBytes, updatedAt }]));
  await store.put(INDEX_PATH, new TextEncoder().encode(JSON.stringify({ version: 1, blobs })), 'application/json; charset=utf-8');
}

// Uploads the attachment files the destination does not have yet. The
// index is saved even when a run fails halfway, so the next one resumes.
async function syncAttachments(deps: Deps, store: RemoteStore, refs: AttachmentRef[]): Promise<void> {
  const index = await readIndex(store);
  const pending = refs.filter((ref) => index.get(ref.blobName) !== ref.sizeBytes);
  if (!pending.length) return;
  try {
    for (let i = 0; i < pending.length; i += FILE_CONCURRENCY) {
      await Promise.all(
        pending.slice(i, i + FILE_CONCURRENCY).map(async (ref) => {
          const object = await deps.blobs.get(attachmentKey(ref.cipherId, ref.attachmentId));
          if (!object) throw new RemoteError(`Attachment file ${ref.blobName} is missing from file storage`);
          const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
          await store.put(remoteAttachmentPath(ref.blobName), bytes, 'application/octet-stream');
          index.set(ref.blobName, ref.sizeBytes);
        }),
      );
    }
  } finally {
    await writeIndex(store, index);
  }
}

// Uploads the archive and reads it back; returns the attempts it took.
async function uploadArchive(store: RemoteStore, archive: Archive): Promise<number> {
  for (let attempt = 1; ; attempt++) {
    await store.put(archive.fileName, archive.bytes, 'application/zip');
    if ((await store.size(archive.fileName).catch(() => null)) === archive.bytes.byteLength) return attempt;
    const stored = await store.get(archive.fileName);
    if (stored?.byteLength === archive.bytes.byteLength && integrityOf(stored, archive.fileName).matches) return attempt;
    await store.delete(archive.fileName).catch(() => undefined);
    if (attempt === UPLOAD_ATTEMPTS) {
      throw new RemoteError(`Backup archive upload verification failed after ${UPLOAD_ATTEMPTS} attempts`);
    }
  }
}

// Removes the oldest archives beyond `keep`; the one just uploaded stays.
async function prune(store: RemoteStore, keep: number | null, current: string): Promise<number> {
  if (keep === null) return 0;
  const time = (value: string | null) => (value ? Date.parse(value) || 0 : 0);
  const archives = (await store.list(''))
    .filter((item) => !item.isDirectory && isArchiveName(item.name))
    .sort(
      (a, b) =>
        Number(b.name === current) - Number(a.name === current) ||
        time(b.modifiedAt) - time(a.modifiedAt) ||
        b.name.localeCompare(a.name, 'en'),
    );
  for (const item of archives.slice(keep)) await store.delete(item.path);
  return Math.max(0, archives.length - keep);
}

function localDate(date: Date, timeZone: string): string {
  return new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(date);
}

// One run, recorded in the destination's history and the audit log. Call
// it holding the lease.
async function run(
  deps: Deps,
  destination: Destination,
  trigger: Trigger,
  actor: { userId: string | null; metadata: Record<string, unknown> },
): Promise<RunResult> {
  const now = new Date();
  await updateRuntime(deps.db, destination.id, {
    lastAttemptAt: now.toISOString(),
    lastAttemptLocalDate: localDate(now, destination.schedule.timezone),
    lastErrorAt: null,
    lastErrorMessage: null,
  });
  const audit = (action: string, metadata: Record<string, unknown>) =>
    recordAudit(deps.db, {
      actorUserId: actor.userId,
      action,
      category: 'data',
      level: action.endsWith('.failed') ? 'error' : 'info',
      targetType: 'backup',
      metadata: { ...destinationSummary(destination), ...metadata, ...actor.metadata },
    });

  try {
    const missing = missingSetting(destination);
    if (missing) throw new RemoteError(missing);
    const store = openStore(deps, destination);
    const archive = await createArchive(deps, now, destination.schedule.timezone, destination.includeAttachments);
    if (destination.includeAttachments) await syncAttachments(deps, store, archive.manifest.attachmentBlobs);
    const attempts = await uploadArchive(store, archive);
    let prunedFileCount = 0;
    let pruneError: string | null = null;
    try {
      prunedFileCount = await prune(store, destination.schedule.retentionCount, archive.fileName);
    } catch (error) {
      pruneError = error instanceof Error ? error.message : 'Old backup cleanup failed';
    }

    const result: RunResult = {
      fileName: archive.fileName,
      fileSize: archive.bytes.byteLength,
      provider: store.provider,
      remotePath: store.location(archive.fileName),
    };
    await updateRuntime(deps.db, destination.id, {
      lastSuccessAt: new Date().toISOString(),
      lastUploadedFileName: result.fileName,
      lastUploadedSizeBytes: result.fileSize,
      lastUploadedDestination: result.remotePath,
    });
    await audit(`admin.backup.remote.${trigger}`, {
      provider: result.provider,
      remotePath: result.remotePath,
      fileName: result.fileName,
      fileBytes: result.fileSize,
      uploadVerificationAttempts: attempts,
      prunedFileCount,
      pruneError,
    });
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup upload failed';
    await updateRuntime(deps.db, destination.id, { lastErrorAt: new Date().toISOString(), lastErrorMessage: message });
    await audit(`admin.backup.remote.${trigger}.failed`, { error: message });
    throw error;
  }
}

// A run an admin started; null while another run or restore holds the lease.
export async function runNow(
  deps: Deps,
  destination: Destination,
  actor: { userId: string; metadata: Record<string, unknown> },
): Promise<RunResult | null> {
  const outcome = await withLease(deps.db, BACKUP_LEASE, BACKUP_LEASE_MS, () => run(deps, destination, 'manual', actor));
  return outcome?.value ?? null;
}

// For the cron job: runs every destination whose slot has passed, one after
// another. Failures are recorded per destination and do not stop the rest.
export async function runScheduledBackups(deps: Deps, now = new Date()): Promise<void> {
  let settings;
  try {
    settings = await loadSettings(deps);
  } catch (error) {
    // Settings restored from another server wait for an admin to repair them.
    console.warn('Scheduled backups skipped:', error instanceof Error ? error.message : error);
    return;
  }
  const due = settings.destinations.filter((destination) => isDue(destination.schedule, destination.runtime, now));
  if (!due.length) return;
  await withLease(deps.db, BACKUP_LEASE, BACKUP_LEASE_MS, async () => {
    for (const destination of due) {
      await run(deps, destination, 'scheduled', { userId: null, metadata: {} }).catch((error) => {
        console.error(`Scheduled backup to ${destination.name} failed:`, error);
      });
    }
  });
}
