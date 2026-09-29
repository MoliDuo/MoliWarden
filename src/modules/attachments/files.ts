import { attachmentKey, type BlobStore } from '../../platform/blob';
import type { Attachment } from './repo';

const CONCURRENCY = 4;

// Removes the files of attachments whose rows are gone. A failure leaves an
// unreferenced file behind and is only logged.
export async function removeAttachmentFiles(blobs: BlobStore, attachments: Attachment[]): Promise<void> {
  for (let i = 0; i < attachments.length; i += CONCURRENCY) {
    await Promise.all(
      attachments.slice(i, i + CONCURRENCY).map((attachment) =>
        blobs.delete(attachmentKey(attachment.cipherId, attachment.id)).catch((error) => {
          console.error('Attachment file delete failed:', attachment.cipherId, attachment.id, error);
        }),
      ),
    );
  }
}
