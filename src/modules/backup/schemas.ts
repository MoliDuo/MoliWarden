import { z } from 'zod';
import { text } from '../../http/body';

// Every change and every read of backup data is confirmed with the admin's
// master password; auth/password says when it is missing. The settings
// themselves are checked by settings.ts, whose messages the web vault
// translates.

const confirmed = { masterPasswordHash: z.string().nullish() };
const destinationId = z.string().nullish().transform((value) => value?.trim() || null);
const flag = z.boolean().nullish().transform((value) => value === true);

export const backupFileBody = z.object(confirmed);
export type BackupFileBody = z.output<typeof backupFileBody>;

export const exportBody = z.object({ ...confirmed, includeAttachments: flag });
export const attachmentFileBody = z.object({ ...confirmed, blobName: text });

export const settingsBody = z.object({ ...confirmed, destinations: z.array(z.unknown()).optional() });
export type SettingsBody = z.output<typeof settingsBody>;

export const repairBody = settingsBody.extend({ userVerificationToken: z.string().nullish() });
export type RepairBody = z.output<typeof repairBody>;

export const runBody = z.object({ ...confirmed, destinationId });
export type RunBody = z.output<typeof runBody>;

export const remoteFileBody = z.object({ ...confirmed, destinationId, path: text });
export type RemoteFileBody = z.output<typeof remoteFileBody>;

export const remoteRestoreBody = remoteFileBody.extend({ replaceExisting: flag, allowChecksumMismatch: flag });
export type RemoteRestoreBody = z.output<typeof remoteRestoreBody>;

export interface ImportForm {
  bytes: Uint8Array<ArrayBuffer>;
  fileName: string;
  replaceExisting: boolean;
  allowChecksumMismatch: boolean;
  masterPasswordHash: string | null;
}
