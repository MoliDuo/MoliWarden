import type { Env } from '../types';
import { PushType } from '../modules/push/service';

// The push calls of the handlers that have not been ported to src/modules
// yet, in the shape they were written against.

interface ItemChange {
  userId: string;
  revisionDate: string;
  organizationId?: string | null;
  collectionIds?: string[] | null;
  contextId?: string | null;
}

function notifyItem(env: Env, type: PushType, id: string, change: ItemChange): void {
  env.PUSH.notify({
    type,
    userId: change.userId,
    deviceIdentifier: change.contextId,
    item: {
      id,
      organizationId: change.organizationId,
      collectionIds: Array.isArray(change.collectionIds) ? change.collectionIds : null,
      revisionDate: change.revisionDate,
    },
  });
}

export function notifyUserVaultSync(env: Env, userId: string, _revisionDate: string, contextId?: string | null): void {
  env.PUSH.notify({ type: PushType.SyncVault, userId, deviceIdentifier: contextId });
}

export function notifyUserCiphersSync(env: Env, userId: string, _revisionDate: string, contextId?: string | null): void {
  env.PUSH.notify({ type: PushType.SyncCiphers, userId, deviceIdentifier: contextId });
}

export const notifyUserCipherCreate = (env: Env, change: ItemChange & { cipherId: string }) =>
  notifyItem(env, PushType.SyncCipherCreate, change.cipherId, change);
export const notifyUserCipherUpdate = (env: Env, change: ItemChange & { cipherId: string }) =>
  notifyItem(env, PushType.SyncCipherUpdate, change.cipherId, change);
export const notifyUserCipherDelete = (env: Env, change: ItemChange & { cipherId: string }) =>
  notifyItem(env, PushType.SyncCipherDelete, change.cipherId, change);
export const notifyUserFolderCreate = (env: Env, change: ItemChange & { folderId: string }) =>
  notifyItem(env, PushType.SyncFolderCreate, change.folderId, change);
export const notifyUserFolderUpdate = (env: Env, change: ItemChange & { folderId: string }) =>
  notifyItem(env, PushType.SyncFolderUpdate, change.folderId, change);
export const notifyUserFolderDelete = (env: Env, change: ItemChange & { folderId: string }) =>
  notifyItem(env, PushType.SyncFolderDelete, change.folderId, change);
export const notifyUserSendCreate = (env: Env, change: ItemChange & { sendId: string }) =>
  notifyItem(env, PushType.SyncSendCreate, change.sendId, change);
export const notifyUserSendUpdate = (env: Env, change: ItemChange & { sendId: string }) =>
  notifyItem(env, PushType.SyncSendUpdate, change.sendId, change);
export const notifyUserSendDelete = (env: Env, change: ItemChange & { sendId: string }) =>
  notifyItem(env, PushType.SyncSendDelete, change.sendId, change);

// Backup progress used to be streamed over the websocket hub; the web vault
// now relies on the HTTP response of the backup request instead.
export async function notifyUserBackupProgress(..._args: unknown[]): Promise<void> {}
export const notifyUserBackupRestoreProgress = notifyUserBackupProgress;
