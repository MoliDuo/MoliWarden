// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s step) for end-to-end tests.
// Self-contained on purpose: tests must not share code with the server.
import { createHmac, randomBytes } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP_STEP_SECONDS = 30;

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`invalid base32 character: ${char}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

export function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >> bits) & 31];
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function randomBase32Secret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function currentCounter(nowMs = Date.now()): number {
  return Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);
}

export function hotp(secretBase32: string, counter: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', base32Decode(secretBase32)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

export function totp(secretBase32: string, nowMs = Date.now()): string {
  return hotp(secretBase32, currentCounter(nowMs));
}

// A 6-digit code that is not valid for any step the server accepts right now
// (it allows one step of drift either way; we exclude two to be safe).
export function wrongTotp(secretBase32: string, nowMs = Date.now()): string {
  const counter = currentCounter(nowMs);
  const valid = new Set<string>();
  for (let delta = -2; delta <= 2; delta++) valid.add(hotp(secretBase32, counter + delta));
  let candidate = Number(hotp(secretBase32, counter));
  let code: string;
  do {
    candidate = (candidate + 1) % 1_000_000;
    code = String(candidate).padStart(6, '0');
  } while (valid.has(code));
  return code;
}

// The server refuses a time step it has already accepted for a user (replay
// protection), no matter which secret produced the code. Hand out codes for
// steps inside the server's +/-1 drift window that this user has not used yet,
// waiting for the clock to move on when all three are spent.
export class TotpCodes {
  private readonly used = new Set<number>();

  async next(secretBase32: string): Promise<{ code: string; counter: number }> {
    for (;;) {
      const now = Date.now();
      const counter = currentCounter(now);
      const msLeftInStep = TOTP_STEP_SECONDS * 1000 - (now % (TOTP_STEP_SECONDS * 1000));
      // The previous step stops being accepted when this one ends; skip it
      // near the boundary.
      const candidates = msLeftInStep > 5000 ? [counter + 1, counter, counter - 1] : [counter + 1, counter];
      for (const candidate of candidates) {
        if (this.used.has(candidate)) continue;
        this.used.add(candidate);
        return { code: hotp(secretBase32, candidate), counter: candidate };
      }
      await new Promise((resolve) => setTimeout(resolve, msLeftInStep + 250));
    }
  }

  markUsed(counter: number): void {
    this.used.add(counter);
  }
}
