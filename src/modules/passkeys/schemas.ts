import { z } from 'zod';
import { text } from '../../http/body';
import { isEncString } from '../../platform/enc-string';
import type { PrfKeySet } from './service';

const secretFields = { masterPasswordHash: text, secret: text, password: text };
const prfFields = { encryptedUserKey: text, encryptedPublicKey: text, encryptedPrivateKey: text };

export const passkeySecretOf = (body: { masterPasswordHash: string; secret: string; password: string }): string | null =>
  body.masterPasswordHash.trim() || body.secret.trim() || body.password.trim() || null;

export const secretBody = z.object(secretFields);

export const assertionOptionsBody = z.object({ ...secretFields, credentialId: text, id: text });

export const createBody = z.object({
  ...prfFields,
  token: text,
  deviceResponse: z.unknown().optional(),
  name: text,
  supportsPrf: z.preprocess((value) => value === true || value === 'true', z.boolean()),
});

export const updateKeysBody = z.object({ ...prfFields, token: text, deviceResponse: z.unknown().optional() });

// Null when the client sent no complete key set, which is not an error:
// the passkey then signs in without unlocking the vault.
export function prfKeySetOf(body: { encryptedUserKey: string; encryptedPublicKey: string; encryptedPrivateKey: string }): PrfKeySet | null | 'invalid' {
  const keys = {
    encryptedUserKey: body.encryptedUserKey.trim(),
    encryptedPublicKey: body.encryptedPublicKey.trim(),
    encryptedPrivateKey: body.encryptedPrivateKey.trim(),
  };
  if (!keys.encryptedUserKey || !keys.encryptedPublicKey || !keys.encryptedPrivateKey) return null;
  return Object.values(keys).every(isEncString) ? keys : 'invalid';
}
