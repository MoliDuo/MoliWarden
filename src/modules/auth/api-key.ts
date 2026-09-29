import { constantTimeEqual, sha256Hex } from '../../platform/crypto';

// The personal API key is stored as issued, since clients show it again.
// Older servers stored "sha256:<hex>" instead; such keys still sign in
// until the data migration clears them.
const LEGACY_HASH_PREFIX = 'sha256:';

export function verifyApiKey(given: string, stored: string | null | undefined): boolean {
  const expected = stored?.trim();
  if (!expected || !given) return false;
  if (expected.startsWith(LEGACY_HASH_PREFIX)) return constantTimeEqual(LEGACY_HASH_PREFIX + sha256Hex(given), expected);
  return constantTimeEqual(given, expected);
}
