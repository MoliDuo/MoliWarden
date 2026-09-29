import { z } from 'zod';
import { encString, integer, isoDate } from '../../http/body';
import { SendType } from './model';

// Bitwarden's SendRequestModel. Fields left out of an update keep their
// values.

const optionalEnc = z
  .string()
  .nullish()
  .transform((value) => value?.trim() || null)
  .refine((value) => value === null || encString.safeParse(value).success, 'Must be an encrypted string.');

export const sendBody = z.object({
  type: z.union([z.literal(SendType.Text), z.literal(SendType.File)], 'Invalid Send type'),
  name: encString,
  notes: optionalEnc.optional(),
  key: encString,
  text: z.object({ text: optionalEnc, hidden: z.boolean().nullish() }).nullish(),
  file: z.object({ fileName: encString }).nullish(),
  // The size of the encrypted file, for new file Sends.
  fileLength: integer.pipe(z.number().nonnegative("Send size can't be negative")).nullish(),
  maxAccessCount: integer.pipe(z.number().nonnegative()).nullish(),
  expirationDate: isoDate.nullish(),
  deletionDate: isoDate,
  // The password hash clients derive from the Send password; '' removes it.
  password: z.string().nullish(),
  authType: integer.nullish(),
  emails: z.string().nullish(),
  disabled: z.boolean().nullish(),
  hideEmail: z.boolean().nullish(),
});
export type SendBody = z.output<typeof sendBody>;

export const sendUpdateBody = sendBody.partial();
export type SendUpdate = z.output<typeof sendUpdateBody>;

// What recipients send to open a password-protected Send.
export const accessBody = z.object({ password: z.string().nullish() });
