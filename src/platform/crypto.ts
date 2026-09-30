import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto';

// The server's own cryptography: hashing, comparison, random tokens, key
// derivation and encryption of secrets at rest. Vault data is end-to-end
// encrypted by the clients and never passes through here.

export type Bytes = Uint8Array | string;

function toBuffer(value: Bytes): Buffer {
  return typeof value === 'string' ? Buffer.from(value, 'utf8') : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

export function base64url(value: Bytes): string {
  return toBuffer(value).toString('base64url');
}

export function fromBase64url(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  return Buffer.from(value, 'base64url');
}

export function sha256(value: Bytes): Buffer {
  return createHash('sha256').update(toBuffer(value)).digest();
}

export function sha256Hex(value: Bytes): string {
  return sha256(value).toString('hex');
}

// Compares digests in constant time, so neither the contents nor the length
// of the inputs leak.
export function constantTimeEqual(a: Bytes, b: Bytes): boolean {
  return timingSafeEqual(sha256(a), sha256(b));
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

const ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
// The largest multiple of 62 below 256; bytes above it would bias the result.
const UNBIASED_LIMIT = 248;

// Letters and digits only, for secrets people copy by hand.
export function randomAlphanumeric(length: number): string {
  let out = '';
  while (out.length < length) {
    for (const byte of randomBytes(length)) {
      if (byte < UNBIASED_LIMIT) out += ALPHANUMERIC[byte % ALPHANUMERIC.length];
      if (out.length === length) break;
    }
  }
  return out;
}

// A key for one purpose, derived from a longer-lived secret.
export function deriveKey(secret: Bytes, purpose: string, length = 32): Buffer {
  return Buffer.from(hkdfSync('sha256', toBuffer(secret), Buffer.alloc(0), `moliwarden.${purpose}`, length));
}

const SEALED_PREFIX = 'mw1.';

// A secret as it is stored: mw1.<iv>.<ciphertext+tag>. The type keeps
// sealed and plain values from being mixed up.
export type Sealed = string & { readonly __sealed: true };

// AES-256-GCM for the secrets the server keeps (2FA seeds, recovery codes,
// API keys, provider credentials). The context names what a value is and
// whose, so a sealed value cannot be moved to another place and still open.
export interface SecretBox {
  seal(plaintext: string, context: string): Sealed;
  open(sealed: Sealed, context: string): string;
}

// A sealed value that does not open: damaged, or sealed under another key.
export class SecretBoxError extends Error {}

export function createSecretBox(encryptionKey: string): SecretBox {
  const key = deriveKey(encryptionKey, 'secret-box');
  return {
    seal(plaintext, context) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(Buffer.from(context, 'utf8'));
      const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
      return `${SEALED_PREFIX}${iv.toString('base64url')}.${body.toString('base64url')}` as Sealed;
    },
    open(sealed, context) {
      const [iv, body] = sealed.startsWith(SEALED_PREFIX) ? sealed.slice(SEALED_PREFIX.length).split('.') : [];
      const ivBytes = iv ? fromBase64url(iv) : null;
      const bodyBytes = body ? fromBase64url(body) : null;
      if (!ivBytes || ivBytes.length !== 12 || !bodyBytes || bodyBytes.length < 16) {
        throw new SecretBoxError(`Malformed sealed secret (${context})`);
      }
      const decipher = createDecipheriv('aes-256-gcm', key, ivBytes, { authTagLength: 16 });
      decipher.setAAD(Buffer.from(context, 'utf8'));
      decipher.setAuthTag(bodyBytes.subarray(bodyBytes.length - 16));
      try {
        return Buffer.concat([decipher.update(bodyBytes.subarray(0, bodyBytes.length - 16)), decipher.final()]).toString('utf8');
      } catch {
        throw new SecretBoxError(`Sealed secret does not open (${context})`);
      }
    },
  };
}
