import { z } from 'zod';
import { encString, text } from '../../http/body';

// A reminder shown before sign-in when the server allows it, so never a
// secret. Blank means none.
const hint = z
  .string()
  .nullish()
  .transform((value) => value?.trim() || null)
  .refine((value) => value === null || value.length <= 120, 'Must be 120 characters or fewer.');

const count = z.number().int().nullish().transform((value) => value ?? null);

const kdf = z.object({ kdfType: z.number().int(), iterations: z.number().int(), memory: count, parallelism: count });

export const registerBody = z.object({
  email: z.string().trim().toLowerCase().min(3, 'Invalid email address.').includes('@', { message: 'Invalid email address.' }),
  name: z.string().nullish().transform((value) => value?.trim() || null),
  masterPasswordHash: z.string().min(1, 'Required.'),
  masterPasswordHint: hint,
  key: encString,
  keys: z.object({ publicKey: z.string().min(1, 'Required.'), encryptedPrivateKey: encString }),
  kdf: z.number().int().default(0),
  kdfIterations: z.number().int().nullish(),
  kdfMemory: z.number().int().nullish(),
  kdfParallelism: z.number().int().nullish(),
  inviteCode: text,
});
export type RegisterInput = z.output<typeof registerBody>;

export const emailBody = z.object({ email: text });

// Official clients send the name with the hint; the web vault only the hint.
export const profileBody = z.object({
  name: z.string().trim().max(50, 'Must be 50 characters or fewer.').optional(),
  masterPasswordHint: hint.optional(),
});

export const keysBody = z.object({
  masterPasswordHash: text,
  key: encString.optional(),
  encryptedPrivateKey: encString.optional(),
  publicKey: z.string().min(1).optional(),
});

// Clients send the new password either as a bare hash and wrapped key, or,
// in newer versions, as authentication and unlock data that also name the
// KDF settings and salt they were derived with.
export const passwordBody = z.object({
  masterPasswordHash: text,
  newMasterPasswordHash: text,
  key: text,
  masterPasswordHint: hint.optional(),
  authenticationData: z.object({ kdf, masterPasswordAuthenticationHash: z.string().min(1), salt: z.string() }).optional(),
  unlockData: z.object({ kdf, masterKeyWrappedUserKey: encString, salt: z.string() }).optional(),
});
export type PasswordInput = z.output<typeof passwordBody>;

export const verifyPasswordBody = z.object({
  masterPasswordHash: text,
  authenticationData: z.object({ masterPasswordAuthenticationHash: text }).optional(),
});

export const userKeyIdBody = z.object({
  userKeyId: z.string().regex(/^[A-Za-z0-9+/=_-]{1,128}$/, 'Invalid key id.'),
});

// The CLI posts these as a form.
export const secretBody = z.object({ masterPasswordHash: text, master_password_hash: text, password: text });
export const secretOf = (body: z.output<typeof secretBody>): string =>
  (body.masterPasswordHash || body.master_password_hash || body.password).trim();
