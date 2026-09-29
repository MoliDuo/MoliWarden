import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { User } from '../../types';
import { touchRevisionDate } from '../accounts/repo';
import { recordAudit, requestMetadata } from '../audit/service';
import { unsetFolders } from '../ciphers/repo';
import { PushType } from '../push/service';
import { deleteFolders, findFolder, listFolders, saveFolders, type Folder } from './repo';
import type { FolderInput } from './schemas';

export function folderJson(folder: Folder) {
  return { id: folder.id, name: folder.name, revisionDate: folder.updatedAt, creationDate: folder.createdAt, object: 'folder' };
}

async function requireFolder(deps: Deps, user: User, id: string): Promise<Folder> {
  const folder = await findFolder(deps.db, user.id, id);
  if (!folder) throw notFound('Folder not found');
  return folder;
}

function notify(deps: Deps, caller: Caller, type: PushType, folderId: string, revisionDate: string) {
  deps.push.notify({ type, userId: caller.user.id, deviceIdentifier: caller.device, item: { id: folderId, revisionDate } });
}

export async function foldersJson(deps: Deps, user: User) {
  return { data: (await listFolders(deps.db, user.id)).map(folderJson), object: 'list', continuationToken: null };
}

export async function folderById(deps: Deps, user: User, id: string) {
  return folderJson(await requireFolder(deps, user, id));
}

export async function saveFolder(deps: Deps, caller: Caller, id: string | null, input: FolderInput) {
  const now = new Date().toISOString();
  const existing = id ? await requireFolder(deps, caller.user, id) : null;
  const folder: Folder = existing
    ? { ...existing, name: input.name, updatedAt: now }
    : { id: randomUUID(), userId: caller.user.id, name: input.name, createdAt: now, updatedAt: now };
  await deps.db.transaction().execute(async (tx) => {
    await saveFolders(tx, [folder]);
    await touchRevisionDate(tx, caller.user.id, now);
  });
  notify(deps, caller, existing ? PushType.SyncFolderUpdate : PushType.SyncFolderCreate, folder.id, now);
  return folderJson(folder);
}

// The ciphers in a deleted folder stay, outside any folder.
export async function removeFolders(deps: Deps, caller: Caller, ids: string[], action = 'folder.delete.bulk'): Promise<void> {
  const now = new Date().toISOString();
  const deleted = await deps.db.transaction().execute(async (tx) => {
    const removed = await deleteFolders(tx, caller.user.id, ids);
    if (!removed.length) return removed;
    await unsetFolders(tx, caller.user.id, removed);
    await touchRevisionDate(tx, caller.user.id, now);
    return removed;
  });
  for (const id of deleted) notify(deps, caller, PushType.SyncFolderDelete, id, now);
  if (!deleted.length) return;
  await recordAudit(deps.db, {
    actorUserId: caller.user.id,
    action,
    category: 'data',
    level: 'security',
    targetType: 'folder',
    targetId: deleted.length === 1 ? deleted[0] : null,
    metadata: { count: deleted.length, ...requestMetadata(caller.request) },
  });
}

export async function removeFolder(deps: Deps, caller: Caller, id: string): Promise<void> {
  await requireFolder(deps, caller.user, id);
  await removeFolders(deps, caller, [id], 'folder.delete');
}
