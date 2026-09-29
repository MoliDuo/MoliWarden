import { z } from 'zod';
import { encString, integer } from '../../http/body';

// Bitwarden's AttachmentRequestModel: the encrypted name and key of a file
// about to be uploaded, and its encrypted size.
export const attachmentBody = z.object({
  fileName: encString,
  key: encString,
  fileSize: integer.pipe(z.number().nonnegative()).nullish(),
});

// Clients re-encrypt the name and key of a file when they repair it.
export const metadataBody = z
  .object({ fileName: encString.optional(), key: encString.nullish() })
  .refine((input) => input.fileName !== undefined || input.key !== undefined, 'No metadata fields supplied');
export type MetadataInput = z.output<typeof metadataBody>;
