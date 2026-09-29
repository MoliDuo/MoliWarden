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
  sizeName: string;
}

function toAttachment(row: Row<'attachments'>): Attachment {
  return {
    id: row.id,
    cipherId: row.cipher_id,
    fileName: row.file_name,
    key: row.key,
    size: Number(row.size) || 0,
    sizeName: row.size_name,
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
