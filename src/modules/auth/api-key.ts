import { constantTimeEqual, type Sealed, type SecretBox } from '../../platform/crypto';
import type { User } from '../../types';

// The personal API key is sealed with ENCRYPTION_KEY rather than hashed,
// since clients show it again.

export const sealApiKey = (box: SecretBox, userId: string, key: string) => box.seal(key, `api-key:${userId}`);
export const openApiKey = (box: SecretBox, userId: string, sealed: Sealed) => box.open(sealed, `api-key:${userId}`);

export function verifyApiKey(box: SecretBox, user: User, given: string): boolean {
  return !!user.apiKey && !!given && constantTimeEqual(given, openApiKey(box, user.id, user.apiKey));
}
