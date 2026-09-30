import { z } from 'zod';
import { encString, text } from '../../http/body';

const identifier = z.string().trim().min(1, 'Required.').max(128, 'Must be 128 characters or fewer.');
const name = z.string().trim().transform((value) => value.slice(0, 128));
// Missing leaves a key as it is; null removes it.
const deviceKey = encString.nullable().optional();

export const keysBody = z.object({
  encryptedUserKey: deviceKey,
  encryptedPublicKey: deviceKey,
  encryptedPrivateKey: deviceKey,
});

export const registerBody = keysBody.extend({
  identifier,
  name: name.optional(),
  type: z.coerce.number().int().min(0),
  pushToken: z.string().trim().optional(),
});
export type RegisterDeviceInput = z.output<typeof registerBody>;

export const nameBody = z.object({ name: name.pipe(z.string().min(1, 'Device name is required')) });

export const pushTokenBody = z.object({ pushToken: z.string().trim().min(1, 'Invalid push token') });

export const secretBody = z.object({ masterPasswordHash: text });

export const lostTrustBody = z.object({ identifier: z.string().trim().optional() });

// Re-encrypted keys after a user key rotation, for this device and others.
export const trustBody = z.object({
  currentDevice: keysBody.nullish(),
  otherDevices: z.array(keysBody.extend({ deviceId: identifier })).nullish(),
});
export type TrustInput = z.output<typeof trustBody>;

export const untrustBody = z.object({ devices: z.array(identifier).default([]) });
