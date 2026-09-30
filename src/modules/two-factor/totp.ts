import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// RFC 6238 authenticator codes: 6 digits, 30-second steps, one step of
// clock drift allowed either way.

const STEP_SECONDS = 30;
const DRIFT_STEPS = 1;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Authenticator apps show secrets in groups, sometimes padded.
export function normalizeTotpSecret(input: string | null | undefined): string {
  return String(input ?? '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
}

function base32Decode(secret: string): Buffer | null {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of normalizeTotpSecret(secret)) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return out.length ? Buffer.from(out) : null;
}

export function isTotpSecret(secret: string | null | undefined): secret is string {
  return !!secret && base32Decode(secret) !== null;
}

export function randomTotpSecret(): string {
  // 32 characters, 160 bits: what authenticator apps expect.
  return Array.from(randomBytes(32), (byte) => ALPHABET[byte % 32]).join('');
}

function code(key: Buffer, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', key).update(message).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

// The time step `input` is the code of, or null. Callers record the step so
// a code works only once.
export function totpStep(secret: string, input: string, now = Date.now()): number | null {
  const given = input.replace(/\s+/g, '');
  const key = base32Decode(secret);
  if (!/^\d{6}$/.test(given) || !key) return null;
  const current = Math.floor(now / 1000 / STEP_SECONDS);
  let match: number | null = null;
  // Every step is checked, so the timing does not tell which one matched.
  for (let step = current - DRIFT_STEPS; step <= current + DRIFT_STEPS; step += 1) {
    if (timingSafeEqual(Buffer.from(code(key, step)), Buffer.from(given)) && match === null) match = step;
  }
  return match;
}

// When a code of `step` stops being accepted.
export function stepExpiry(step: number): Date {
  return new Date((step + DRIFT_STEPS + 1) * STEP_SECONDS * 1000);
}
