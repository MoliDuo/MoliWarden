import type { Caller } from '../../http/authenticate';
import { badRequest, conflict } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { attachmentKey } from '../../platform/blob';
import { removeAttachmentFiles } from '../attachments/files';
import { listSends } from '../sends/repo';
import { removeSendFiles } from '../sends/service';
import { attachmentEntry, KIND_NAMES, type KindName, type ParsedArchive } from './archive';
import { hasVaultData, listAttachmentKeys, replaceInstance } from './repo';

// Restoring replaces every account and vault on the server with the
// backup's. Attachment files are uploaded first and the rows replaced in
// one transaction, so a failed restore leaves the server as it was; the
// files the restored data no longer references are removed after.

const UPLOAD_CONCURRENCY = 4;
const STORAGE_MISSING = 'Attachment storage is not configured';
const SOME_FILES_FAILED = 'Some attachments could not be restored and were skipped';
const EXTERNAL_FILES = 'Attachment files stored next to a remote backup are only restored from that destination';

export interface RestoreResult {
  object: 'instance-backup-import';
  imported: Record<KindName, number> & { attachmentFiles: number };
  skipped: {
    reason: string | null;
    attachments: number;
    items: Array<{ kind: 'attachment'; path: string; sizeBytes: number }>;
  };
}

export interface RestoreOptions {
  replaceExisting: boolean;
  // Reads a file stored outside the archive; without it those are skipped.
  fetchExternal: ((blobName: string) => Promise<Uint8Array<ArrayBuffer> | null>) | null;
}

// Uploads the attachment files; returns the keys uploaded and why the rest
// were not.
async function uploadFiles(deps: Deps, archive: ParsedArchive, options: RestoreOptions) {
  const uploaded = new Set<string>();
  const failed = new Map<string, string>();
  const records = archive.snapshot.attachments;
  for (let i = 0; i < records.length; i += UPLOAD_CONCURRENCY) {
    await Promise.all(
      records.slice(i, i + UPLOAD_CONCURRENCY).map(async (record) => {
        const key = attachmentKey(String(record.cipherId), String(record.id));
        if (!deps.blobs.configured) return void failed.set(key, STORAGE_MISSING);
        const external = archive.external.get(key);
        if (external && !options.fetchExternal) return void failed.set(key, EXTERNAL_FILES);
        try {
          const bytes = archive.files.get(key) ?? (await options.fetchExternal!(external!));
          if (!bytes) return void failed.set(key, SOME_FILES_FAILED);
          await deps.blobs.put(key, bytes);
          uploaded.add(key);
        } catch (error) {
          console.error('Restoring attachment file failed:', key, error);
          failed.set(key, SOME_FILES_FAILED);
        }
      }),
    );
  }
  return { uploaded, failed };
}

// Postgres refuses rows that contradict each other (a cipher in a folder of
// another user, two users with one email, ...): the backup is inconsistent.
function isDataError(error: unknown): error is { code: string; table?: string } {
  const code = (error as { code?: unknown })?.code;
  return typeof code === 'string' && (code.startsWith('22') || code.startsWith('23'));
}

export async function restoreArchive(deps: Deps, caller: Caller, archive: ParsedArchive, options: RestoreOptions) {
  if (!options.replaceExisting && (await hasVaultData(deps.db))) {
    throw conflict('Backup import requires a fresh instance with no vault or send data');
  }
  const previousFiles = await listAttachmentKeys(deps.db);
  const previousSends = await listSends(deps.db, null);

  const { uploaded, failed } = await uploadFiles(deps, archive, options);
  const snapshot = {
    ...archive.snapshot,
    attachments: archive.snapshot.attachments.filter((record) => uploaded.has(attachmentKey(String(record.cipherId), String(record.id)))),
  };
  const kept = new Set(previousFiles.map((file) => attachmentKey(file.cipherId, file.id)));
  try {
    await deps.db.transaction().execute((tx) => replaceInstance(tx, snapshot));
  } catch (error) {
    const orphans = [...uploaded].filter((key) => !kept.has(key)).map((key) => ({ cipherId: key.split('/')[0], id: key.split('/')[1] }));
    await removeAttachmentFiles(deps.blobs, orphans);
    if (!isDataError(error)) throw error;
    throw badRequest(`Invalid backup: records in ${error.table ?? 'a table'} contradict the rest of the backup`);
  }

  await removeAttachmentFiles(
    deps.blobs,
    previousFiles.filter((file) => !uploaded.has(attachmentKey(file.cipherId, file.id))),
  );
  await removeSendFiles(deps.blobs, previousSends);

  const skipped = archive.snapshot.attachments.filter((record) => failed.has(attachmentKey(String(record.cipherId), String(record.id))));
  const reasons = new Set(failed.values());
  const result: RestoreResult = {
    object: 'instance-backup-import',
    imported: {
      ...(Object.fromEntries(KIND_NAMES.map((kind) => [kind, snapshot[kind].length])) as Record<KindName, number>),
      attachmentFiles: uploaded.size,
    },
    skipped: {
      reason: reasons.size === 1 ? [...reasons][0] : reasons.size ? SOME_FILES_FAILED : null,
      attachments: skipped.length,
      items: skipped.map((record) => ({
        kind: 'attachment',
        path: attachmentEntry(String(record.cipherId), String(record.id)),
        sizeBytes: Number(record.size) || 0,
      })),
    },
  };
  // The admin who restored is only named in the log if the backup has them.
  const actorUserId = snapshot.users.some((user) => user.id === caller.user.id) ? caller.user.id : null;
  return { result, actorUserId };
}
