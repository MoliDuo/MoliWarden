import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, conflict, notFound, notImplemented } from '../../http/errors';
import type { Upload } from '../../http/files';
import { listJson } from '../../http/list';
import type { Deps } from '../../main/deps';
import { BLOB_STORAGE_MISSING, sendFileKey, type BlobStore } from '../../platform/blob';
import { recordAudit, requestMetadata } from '../audit/service';
import { PushType } from '../push/service';
import { commit } from '../sync/changes';
import { SendAuthType, SendType, hashSendPassword, type Send } from './model';
import { deleteSends, findSend, listSends, saveSend } from './repo';
import { sendJson } from './responses';
import type { SendBody, SendUpdate } from './schemas';

// The Sends of their owner. What recipients do is in access.ts.

const MAX_DELETION_DAYS = 31;
// Leeway for the clocks of client and server.
const CLOCK_LEEWAY_MS = 60_000;

const SEND_NOT_FOUND = 'Send not found';
const EMAIL_AUTH_UNSUPPORTED = 'Send email verification is not supported by this server.';

async function requireSend(deps: Deps, caller: Caller, id: string, message = SEND_NOT_FOUND): Promise<Send> {
  const send = await findSend(deps.db, id);
  if (!send || send.userId !== caller.user.id) throw notFound(message);
  return send;
}

function checkDeletionDate(date: string, now: number): void {
  const time = Date.parse(date);
  if (time <= now + CLOCK_LEEWAY_MS) {
    throw badRequest('You cannot have a Send with a deletion date in the past. Adjust the Deletion Date and try again.');
  }
  if (time > now + MAX_DELETION_DAYS * 86_400_000) {
    throw badRequest(
      'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.',
    );
  }
}

// Only a password can guard a Send here; the server sends no email.
function checkAuth(input: Pick<SendUpdate, 'authType' | 'emails'>): void {
  if (input.authType === SendAuthType.Email || input.emails?.trim()) throw notImplemented(EMAIL_AUTH_UNSUPPORTED);
}

// A non-empty password sets it, '' removes it, and none keeps it.
async function withPassword(send: Send, input: Pick<SendUpdate, 'password' | 'authType'>): Promise<Send> {
  const password =
    input.password === '' ? null : input.password ? await hashSendPassword(input.password) : send.password;
  if (input.authType === SendAuthType.Password && !password) throw badRequest('Password is required for password auth');
  return { ...send, password };
}

const changed = (type: PushType, send: Send) => ({ push: { type, item: { id: send.id, revisionDate: send.updatedAt } } });

function audit(deps: Deps, caller: Caller, action: string, targetId: string | null, metadata: Record<string, unknown>) {
  return recordAudit(deps.db, {
    actorUserId: caller.user.id,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'send',
    targetId,
    metadata: { ...metadata, ...requestMetadata(caller.request) },
  });
}

export async function sendsJson(deps: Deps, caller: Caller) {
  return listJson((await listSends(deps.db, caller.user.id)).map(sendJson));
}

export async function sendById(deps: Deps, caller: Caller, id: string) {
  return sendJson(await requireSend(deps, caller, id));
}

async function create(deps: Deps, caller: Caller, input: SendBody, content: Pick<Send, 'type' | 'text' | 'file'>): Promise<Send> {
  checkAuth(input);
  const now = new Date();
  if (input.expirationDate && Date.parse(input.expirationDate) <= now.getTime() + CLOCK_LEEWAY_MS) {
    throw badRequest('You cannot create a Send that is already expired. Adjust the expiration date and try again.');
  }
  checkDeletionDate(input.deletionDate, now.getTime());
  const date = now.toISOString();
  const send = await withPassword(
    {
      id: randomUUID(),
      userId: caller.user.id,
      ...content,
      name: input.name,
      notes: input.notes ?? null,
      key: input.key,
      password: null,
      maxAccessCount: input.maxAccessCount ?? null,
      accessCount: 0,
      disabled: input.disabled ?? false,
      hideEmail: input.hideEmail ?? false,
      createdAt: date,
      updatedAt: date,
      expirationDate: input.expirationDate ?? null,
      deletionDate: input.deletionDate,
    },
    input,
  );
  await commit(deps, caller, date, changed(PushType.SyncSendCreate, send), (tx) => saveSend(tx, send));
  return send;
}

export async function createTextSend(deps: Deps, caller: Caller, input: SendBody) {
  if (input.type !== SendType.Text) throw badRequest('File sends should use /api/sends/file/v2');
  if (!input.text) throw badRequest('Send data not provided');
  const text = { text: input.text.text, hidden: input.text.hidden ?? false };
  return sendJson(await create(deps, caller, input, { type: SendType.Text, text, file: null }));
}

// The file is uploaded next, to the URL the answer carries.
export async function createFileSend(deps: Deps, caller: Caller, input: SendBody): Promise<Send> {
  if (input.type !== SendType.File) throw badRequest('Send content is not a file');
  if (!deps.blobs.configured) throw badRequest(BLOB_STORAGE_MISSING);
  if (input.fileLength == null) throw badRequest('Invalid send length');
  if (input.fileLength > deps.config.maxUploadBytes) throw badRequest('Send storage limit exceeded with this file');
  if (!input.file) throw badRequest('Send data not provided');
  const file = { id: randomUUID(), fileName: input.file.fileName, size: input.fileLength };
  return create(deps, caller, input, { type: SendType.File, text: null, file });
}

export async function updateSend(deps: Deps, caller: Caller, id: string, input: SendUpdate) {
  const current = await requireSend(deps, caller, id);
  if (input.type !== undefined && input.type !== current.type) throw badRequest("Sends can't change type");
  checkAuth(input);
  const now = new Date();
  if (input.deletionDate) checkDeletionDate(input.deletionDate, now.getTime());
  const send = await withPassword(
    {
      ...current,
      name: input.name ?? current.name,
      notes: input.notes === undefined ? current.notes : input.notes,
      key: input.key ?? current.key,
      // A file stays as it was uploaded.
      text: current.text && input.text ? { text: input.text.text, hidden: input.text.hidden ?? false } : current.text,
      maxAccessCount: input.maxAccessCount === undefined ? current.maxAccessCount : input.maxAccessCount,
      expirationDate: input.expirationDate === undefined ? current.expirationDate : input.expirationDate,
      deletionDate: input.deletionDate ?? current.deletionDate,
      disabled: input.disabled ?? current.disabled,
      hideEmail: input.hideEmail ?? current.hideEmail,
      updatedAt: now.toISOString(),
    },
    input,
  );
  await commit(deps, caller, send.updatedAt, changed(PushType.SyncSendUpdate, send), (tx) => saveSend(tx, send));
  return sendJson(send);
}

// Recipients no longer need a password; there is no other way to guard a
// Send here.
export async function removeSendPassword(deps: Deps, caller: Caller, id: string, action: 'send.password.remove' | 'send.auth.remove') {
  const current = await requireSend(deps, caller, id);
  const send = { ...current, password: null, updatedAt: new Date().toISOString() };
  await commit(deps, caller, send.updatedAt, changed(PushType.SyncSendUpdate, send), (tx) => saveSend(tx, send));
  await audit(deps, caller, action, send.id, { type: send.type });
  return sendJson(send);
}

// Removes the files of Sends whose rows are gone. A failure leaves an
// unreferenced file behind and is only logged.
export async function removeSendFiles(blobs: BlobStore, sends: Send[]): Promise<void> {
  for (const send of sends) {
    if (!send.file?.id) continue;
    await blobs.delete(sendFileKey(send.id, send.file.id)).catch((error) => {
      console.error('Send file delete failed:', send.id, error);
    });
  }
}

async function remove(deps: Deps, caller: Caller, sends: Send[]): Promise<void> {
  if (!sends.length) return;
  const date = new Date().toISOString();
  const push =
    sends.length === 1 ? changed(PushType.SyncSendDelete, { ...sends[0], updatedAt: date }) : { push: { type: PushType.SyncVault } };
  await commit(deps, caller, date, push, (tx) =>
    deleteSends(
      tx,
      caller.user.id,
      sends.map((send) => send.id),
    ),
  );
  await removeSendFiles(deps.blobs, sends);
}

export async function deleteSend(deps: Deps, caller: Caller, id: string): Promise<void> {
  const send = await requireSend(deps, caller, id);
  await remove(deps, caller, [send]);
  await audit(deps, caller, 'send.delete', send.id, { type: send.type });
}

// Ids of other users' Sends are passed over.
export async function deleteSendsById(deps: Deps, caller: Caller, ids: string[]): Promise<void> {
  const sends = await listSends(deps.db, caller.user.id, ids);
  await remove(deps, caller, sends);
  if (sends.length) await audit(deps, caller, 'send.delete.bulk', null, { count: sends.length, requestedCount: ids.length });
}

// The file Send whose file is still to be uploaded under `fileId`.
export async function requireFileSend(deps: Deps, caller: Caller, id: string, fileId: string, message = SEND_NOT_FOUND): Promise<Send> {
  const send = await requireSend(deps, caller, id, message);
  if (!send.file) throw badRequest('Send is not a file type send.');
  if (send.file.id !== fileId) throw badRequest('Send file does not match send data.');
  return send;
}

export async function uploadSendFile(
  deps: Deps,
  caller: Caller,
  id: string,
  fileId: string,
  read: (expectedSize: number) => Promise<Upload>,
): Promise<void> {
  const send = await requireFileSend(deps, caller, id, fileId, 'Send not found. Unable to save the file.');
  const key = sendFileKey(send.id, fileId);
  if (await deps.blobs.head(key)) throw conflict('Send file has already been uploaded');
  const upload = await read(send.file!.size);
  await deps.blobs.put(key, upload.bytes, upload.contentType);
  const date = new Date().toISOString();
  await commit(deps, caller, date, changed(PushType.SyncSendUpdate, { ...send, updatedAt: date }), async () => {});
}
