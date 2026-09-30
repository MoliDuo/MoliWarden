import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';

// File attachments of ciphers. The files themselves are in blob storage
// under "<cipher>/<attachment>".

export interface Attachment {
  id: string;
  cipherId: string;
  // Encrypted, like the key the file is encrypted with.
  fileName: string;
  key: string | null;
  size: number;
  // Null until the file is in blob storage.
  uploadedAt: string | null;
  createdAt: string;
}

function toAttachment(row: Row<'attachments'>): Attachment {
  return {
    id: row.id,
    cipherId: row.cipher_id,
    fileName: row.file_name,
    key: row.key,
    size: row.size,
    uploadedAt: row.uploaded_at,
    createdAt: row.created_at,
  };
}

// cipher id -> its attachments.
export async function listAttachments(db: Executor, cipherIds: string[]): Promise<Map<string, Attachment[]>> {
  const byCipher = new Map<string, Attachment[]>();
  if (!cipherIds.length) return byCipher;
  const rows = await db
    .selectFrom('attachments')
    .selectAll()
    .where((eb) => eb('cipher_id', '=', eb.fn.any(eb.val(cipherIds))))
    .orderBy('id')
    .execute();
  for (const attachment of rows.map(toAttachment)) {
    const list = byCipher.get(attachment.cipherId);
    if (list) list.push(attachment);
    else byCipher.set(attachment.cipherId, [attachment]);
  }
  return byCipher;
}

// Names and keys are re-encrypted when their cipher gets its own key or
// moves to an organization.
export async function renameAttachments(
  db: Executor,
  cipherId: string,
  changes: Array<{ id: string; fileName?: string | null; key?: string | null }>,
): Promise<void> {
  for (const change of changes) {
    const set: { file_name?: string; key?: string | null } = {};
    if (change.fileName) set.file_name = change.fileName;
    if (change.key !== undefined) set.key = change.key;
    if (!Object.keys(set).length) continue;
    await db.updateTable('attachments').set(set).where('id', '=', change.id).where('cipher_id', '=', cipherId).execute();
  }
}

export async function findAttachment(db: Executor, cipherId: string, id: string): Promise<Attachment | null> {
  const row = await db.selectFrom('attachments').selectAll().where('id', '=', id).where('cipher_id', '=', cipherId).executeTakeFirst();
  return row ? toAttachment(row) : null;
}

export async function saveAttachment(db: Executor, attachment: Attachment): Promise<void> {
  const row = {
    id: attachment.id,
    cipher_id: attachment.cipherId,
    file_name: attachment.fileName,
    key: attachment.key,
    size: attachment.size,
    uploaded_at: attachment.uploadedAt,
    created_at: attachment.createdAt,
  };
  await db
    .insertInto('attachments')
    .values(row)
    .onConflict((oc) =>
      oc.column('id').doUpdateSet({ file_name: row.file_name, key: row.key, size: row.size, uploaded_at: row.uploaded_at }),
    )
    .execute();
}

export async function deleteAttachment(db: Executor, id: string): Promise<void> {
  await db.deleteFrom('attachments').where('id', '=', id).execute();
}

// Attachments created before `before` whose file never arrived, with the
// owner of their cipher.
export async function findAbandonedUploads(
  db: Executor,
  before: string,
): Promise<Array<{ id: string; cipherId: string; userId: string | null; organizationId: string | null }>> {
  return db
    .selectFrom('attachments')
    .innerJoin('ciphers', 'ciphers.id', 'attachments.cipher_id')
    .select(['attachments.id', 'attachments.cipher_id as cipherId', 'ciphers.user_id as userId', 'ciphers.organization_id as organizationId'])
    .where('attachments.uploaded_at', 'is', null)
    .where('attachments.created_at', '<', before)
    .execute();
}

// Deletes those of `ids` still waiting for their file.
export async function deleteAbandonedUploads(db: Executor, ids: string[], before: string): Promise<Array<{ id: string; cipherId: string }>> {
  if (!ids.length) return [];
  return db
    .deleteFrom('attachments')
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(ids))))
    .where('uploaded_at', 'is', null)
    .where('created_at', '<', before)
    .returning(['id', 'cipher_id as cipherId'])
    .execute();
}
