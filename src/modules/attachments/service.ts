import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, conflict, forbidden, notFound, unauthorized } from '../../http/errors';
import { FILE_TOKEN_TTL_SECONDS, fileDownload, maxSizeName, sizeName, type Upload } from '../../http/files';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { attachmentKey, BLOB_STORAGE_MISSING } from '../../platform/blob';
import { recordAudit, requestMetadata } from '../audit/service';
import { useTokenOnce } from '../auth/repo';
import { touchCipher } from '../ciphers/repo';
import { attachmentJson } from '../ciphers/responses';
import { canEdit, requireView, viewJson, type CipherView } from '../ciphers/views';
import { pushItem } from '../ciphers/writes';
import { loadOrgContext } from '../organizations/access';
import { PushType } from '../push/service';
import { commit } from '../sync/changes';
import { removeAttachmentFiles } from './files';
import { deleteAttachment, findAttachment, saveAttachment, type Attachment } from './repo';
import type { MetadataInput } from './schemas';

// Files attached to ciphers. Whoever can edit a cipher can change its
// attachments; whoever can see it can download them.

const NOT_FOUND = 'Attachment not found';

type DownloadClaims = { file: string; jti: string };

async function requireCipher(deps: Deps, caller: Caller, cipherId: string, write: boolean): Promise<CipherView> {
  const view = await requireView(deps.db, await loadOrgContext(deps.db, caller.user.id), cipherId);
  if (write && !canEdit(view)) throw forbidden('You do not have permission to modify this item');
  return view;
}

async function requireAttachment(deps: Deps, cipherId: string, id: string): Promise<Attachment> {
  const attachment = await findAttachment(deps.db, cipherId, id);
  if (!attachment) throw notFound(NOT_FOUND);
  return attachment;
}

// The cipher changes with its attachments, for everyone who sees it.
async function changeCipher(deps: Deps, caller: Caller, view: CipherView, write: (tx: Executor) => Promise<void>): Promise<CipherView> {
  const date = new Date().toISOString();
  const cipher = { ...view.cipher, updatedAt: date };
  const change = {
    orgIds: [cipher.organizationId],
    push: { type: PushType.SyncCipherUpdate, item: pushItem(cipher, view.access.collectionIds) },
  };
  await commit(deps, caller, date, change, async (tx) => {
    await write(tx);
    await touchCipher(tx, cipher.id, date);
  });
  return { ...view, cipher };
}

const tooLarge = (deps: Deps) => `File too large. Maximum size is ${maxSizeName(deps.config.maxUploadBytes)}`;

// The file is uploaded next, to the URL the answer carries.
export async function createAttachment(deps: Deps, caller: Caller, cipherId: string, input: { fileName: string; key: string; fileSize?: number | null }) {
  const view = await requireCipher(deps, caller, cipherId, true);
  if (!deps.blobs.configured) throw badRequest(BLOB_STORAGE_MISSING);
  const size = input.fileSize ?? 0;
  // Too large a body would be cut off by the platform and leave a broken
  // attachment behind.
  if (size > deps.config.maxUploadBytes) throw badRequest(tooLarge(deps));
  const attachment: Attachment = { id: randomUUID(), cipherId, fileName: input.fileName, key: input.key, size, sizeName: sizeName(size) };
  const changed = await changeCipher(deps, caller, view, (tx) => saveAttachment(tx, attachment));
  return { attachment, cipherResponse: await viewJson(deps.db, changed) };
}

export const uploadLimits = (deps: Deps) => ({ maxBytes: deps.config.maxUploadBytes, tooLarge: tooLarge(deps) });

export async function uploadAttachment(
  deps: Deps,
  caller: Caller,
  cipherId: string,
  id: string,
  read: (expectedSize: number | null) => Promise<Upload>,
): Promise<void> {
  const view = await requireCipher(deps, caller, cipherId, true);
  const attachment = await requireAttachment(deps, cipherId, id);
  const key = attachmentKey(cipherId, id);
  if (await deps.blobs.head(key)) throw conflict('Attachment file has already been uploaded');
  // Clients that did not announce the size get it recorded now.
  const upload = await read(attachment.size || null);
  await deps.blobs.put(key, upload.bytes, upload.contentType);
  const size = upload.bytes.byteLength;
  await changeCipher(deps, caller, view, (tx) => saveAttachment(tx, { ...attachment, size, sizeName: sizeName(size) }));
}

// Where to download the file, good for one download.
export async function attachmentDownloadInfo(deps: Deps, caller: Caller, origin: string, cipherId: string, id: string) {
  await requireCipher(deps, caller, cipherId, false);
  const attachment = await requireAttachment(deps, cipherId, id);
  const token = deps.tokens.sign<DownloadClaims>(
    'attachment-download',
    { file: attachmentKey(cipherId, id), jti: randomUUID() },
    FILE_TOKEN_TTL_SECONDS,
  );
  return { ...attachmentJson(attachment), url: `${origin}/api/attachments/${cipherId}/${id}?token=${token}` };
}

export async function downloadAttachment(deps: Deps, cipherId: string, id: string, token: string | null): Promise<Response> {
  if (!token) throw unauthorized('Token required');
  const claims = deps.tokens.verify<DownloadClaims>('attachment-download', token);
  if (!claims) throw unauthorized('Invalid or expired token');
  const key = attachmentKey(cipherId, id);
  if (claims.file !== key) throw unauthorized('Token mismatch');
  const attachment = await requireAttachment(deps, cipherId, id);
  if (!(await useTokenOnce(deps.db, claims.jti, claims.exp))) throw unauthorized('Invalid or expired token');
  return fileDownload(deps.blobs, key, attachment.fileName || 'attachment', 'Attachment file not found');
}

export async function updateAttachmentMetadata(deps: Deps, caller: Caller, cipherId: string, id: string, input: MetadataInput) {
  const view = await requireCipher(deps, caller, cipherId, true);
  const current = await requireAttachment(deps, cipherId, id);
  const attachment = { ...current, fileName: input.fileName ?? current.fileName, key: input.key === undefined ? current.key : input.key };
  await changeCipher(deps, caller, view, (tx) => saveAttachment(tx, attachment));
  return attachmentJson(attachment);
}

export async function removeAttachment(deps: Deps, caller: Caller, cipherId: string, id: string) {
  const view = await requireCipher(deps, caller, cipherId, true);
  const attachment = await requireAttachment(deps, cipherId, id);
  const changed = await changeCipher(deps, caller, view, (tx) => deleteAttachment(tx, id));
  await removeAttachmentFiles(deps.blobs, [attachment]);
  await recordAudit(deps.db, {
    actorUserId: caller.user.id,
    action: 'attachment.delete',
    category: 'data',
    level: 'security',
    targetType: 'attachment',
    targetId: id,
    metadata: { cipherId, size: attachment.size, ...requestMetadata(caller.request) },
  });
  return { cipher: await viewJson(deps.db, changed), object: 'deleteAttachment' };
}
