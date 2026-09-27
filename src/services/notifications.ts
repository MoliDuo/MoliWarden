import type { Env } from '../types';
import { runInBackground } from '../platform/background';
import { notifyMobilePush } from './push-relay';

// Vercel Functions cannot hold WebSocket connections, so the SignalR hub from
// upstream NodeWarden is gone. Desktop / browser clients pick up changes on
// their regular sync; mobile clients still get pushes through the official
// Bitwarden push relay (when the installation is registered).
//
// The exported API mirrors the old Durable Object helpers so call sites stay
// unchanged.

const UPDATE_TYPE_SYNC_CIPHER_UPDATE = 0;
const UPDATE_TYPE_SYNC_CIPHER_CREATE = 1;
const UPDATE_TYPE_SYNC_FOLDER_DELETE = 3;
const UPDATE_TYPE_SYNC_CIPHERS = 4;
const UPDATE_TYPE_SYNC_VAULT = 5;
const UPDATE_TYPE_SYNC_FOLDER_CREATE = 7;
const UPDATE_TYPE_SYNC_FOLDER_UPDATE = 8;
const UPDATE_TYPE_SYNC_CIPHER_DELETE = 9;
const UPDATE_TYPE_LOG_OUT = 11;
const UPDATE_TYPE_SYNC_SEND_CREATE = 12;
const UPDATE_TYPE_SYNC_SEND_UPDATE = 13;
const UPDATE_TYPE_SYNC_SEND_DELETE = 14;
const UPDATE_TYPE_AUTH_REQUEST = 15;

export function notifyUserVaultSync(
  env: Env,
  userId: string,
  revisionDate: string,
  contextId?: string | null
): void {
  runInBackground(notifyUserUpdate(env, userId, UPDATE_TYPE_SYNC_VAULT, revisionDate, contextId ?? null, null));
}

export function notifyUserCiphersSync(
  env: Env,
  userId: string,
  revisionDate: string,
  contextId?: string | null
): void {
  runInBackground(notifyUserUpdate(env, userId, UPDATE_TYPE_SYNC_CIPHERS, revisionDate, contextId ?? null, null));
}

export function notifyUserCipherCreate(
  env: Env,
  payload: {
    userId: string;
    cipherId: string;
    revisionDate: string;
    organizationId?: string | null;
    collectionIds?: string[] | null;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_CIPHER_CREATE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.cipherId,
      OrganizationId: payload.organizationId ?? null,
      CollectionIds: Array.isArray(payload.collectionIds) ? payload.collectionIds : null,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserCipherUpdate(
  env: Env,
  payload: {
    userId: string;
    cipherId: string;
    revisionDate: string;
    organizationId?: string | null;
    collectionIds?: string[] | null;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_CIPHER_UPDATE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.cipherId,
      OrganizationId: payload.organizationId ?? null,
      CollectionIds: Array.isArray(payload.collectionIds) ? payload.collectionIds : null,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserCipherDelete(
  env: Env,
  payload: {
    userId: string;
    cipherId: string;
    revisionDate: string;
    organizationId?: string | null;
    collectionIds?: string[] | null;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_CIPHER_DELETE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.cipherId,
      OrganizationId: payload.organizationId ?? null,
      CollectionIds: Array.isArray(payload.collectionIds) ? payload.collectionIds : null,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserFolderCreate(
  env: Env,
  payload: {
    userId: string;
    folderId: string;
    revisionDate: string;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_FOLDER_CREATE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.folderId,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserFolderUpdate(
  env: Env,
  payload: {
    userId: string;
    folderId: string;
    revisionDate: string;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_FOLDER_UPDATE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.folderId,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserFolderDelete(
  env: Env,
  payload: {
    userId: string;
    folderId: string;
    revisionDate: string;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_FOLDER_DELETE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.folderId,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserSendCreate(
  env: Env,
  payload: {
    userId: string;
    sendId: string;
    revisionDate: string;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_SEND_CREATE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.sendId,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserSendUpdate(
  env: Env,
  payload: {
    userId: string;
    sendId: string;
    revisionDate: string;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_SEND_UPDATE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.sendId,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserSendDelete(
  env: Env,
  payload: {
    userId: string;
    sendId: string;
    revisionDate: string;
    contextId?: string | null;
  }
): void {
  runInBackground(notifyUserUpdate(
    env,
    payload.userId,
    UPDATE_TYPE_SYNC_SEND_DELETE,
    payload.revisionDate,
    payload.contextId ?? null,
    null,
    {
      UserId: payload.userId,
      Id: payload.sendId,
      RevisionDate: payload.revisionDate,
    }
  ));
}

export function notifyUserLogout(
  env: Env,
  userId: string,
  targetDeviceIdentifier?: string | null
): void {
  runInBackground(notifyUserUpdate(env, userId, UPDATE_TYPE_LOG_OUT, new Date().toISOString(), null, targetDeviceIdentifier ?? null));
}

export async function getOnlineUserDevices(_env: Env, _userId: string): Promise<string[]> {
  return [];
}

export async function notifyAuthRequestResponse(
  _env: Env,
  _userId: string,
  _authRequestId: string,
  _contextId?: string | null
): Promise<void> {
  // Requesting devices poll GET /api/auth-requests/{id}/response instead.
}

export function notifyUserAuthRequest(
  env: Env,
  userId: string,
  authRequestId: string,
  contextId?: string | null
): void {
  runInBackground(notifyUserUpdate(
    env,
    userId,
    UPDATE_TYPE_AUTH_REQUEST,
    new Date().toISOString(),
    contextId ?? null,
    null,
    {
      UserId: userId,
      Id: authRequestId,
    }
  ));
}

async function notifyUserUpdate(
  env: Env,
  userId: string,
  updateType: number,
  revisionDate: string,
  contextId: string | null,
  _targetDeviceIdentifier: string | null,
  payloadOverride?: Record<string, unknown> | null
): Promise<void> {
  try {
    await notifyMobilePush(env, {
      userId,
      updateType,
      revisionDate,
      contextId,
      payload: payloadOverride || {
        UserId: userId,
        Date: revisionDate,
      },
    });
  } catch (error) {
    console.error('Failed to send push notification:', error);
  }
}

export async function notifyUserBackupProgress(
  env: Env,
  userId: string,
  progress: {
    operation: 'backup-restore' | 'backup-export' | 'backup-remote-run';
    source?: 'local' | 'remote';
    step: string;
    fileName: string;
    stageTitle?: string;
    stageDetail?: string;
    replaceExisting?: boolean;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
    timestamp?: string;
  },
  targetDeviceIdentifier?: string | null
): Promise<void> {
  // Progress used to be streamed over the websocket hub; the web vault now
  // relies on the HTTP response of the backup request instead.
  void env;
  void userId;
  void progress;
  void targetDeviceIdentifier;
}

export async function notifyUserBackupRestoreProgress(
  env: Env,
  userId: string,
  progress: {
    operation: 'backup-restore';
    source: 'local' | 'remote';
    step: string;
    fileName: string;
    stageTitle?: string;
    stageDetail?: string;
    replaceExisting?: boolean;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
    timestamp?: string;
  },
  targetDeviceIdentifier?: string | null
): Promise<void> {
  return notifyUserBackupProgress(env, userId, progress, targetDeviceIdentifier);
}
