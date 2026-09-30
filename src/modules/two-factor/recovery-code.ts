import { randomInt } from 'node:crypto';
import { constantTimeEqual } from '../../platform/crypto';

// The one-time code that turns two-step login off when every other factor
// is lost: 32 base32 characters in groups of four.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const compact = (code: string) => code.toUpperCase().replace(/[^A-Z2-7]/g, '');

export function createRecoveryCode(): string {
  const chars = Array.from({ length: 32 }, () => ALPHABET[randomInt(ALPHABET.length)]).join('');
  return chars.replace(/(.{4})(?!$)/g, '$1 ');
}

export function recoveryCodeMatches(input: string, stored: string | null): boolean {
  return !!stored && !!compact(input) && constantTimeEqual(compact(input), compact(stored));
}
