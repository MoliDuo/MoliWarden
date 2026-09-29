import { constants, createCipheriv, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto';
import type { Sealed as SealedSecret, SecretBox } from '../../platform/crypto';
import type { User } from '../../types';

// Backup settings hold the destinations' credentials, so they are stored
// encrypted, twice:
// - runtime: sealed with ENCRYPTION_KEY, for this server's own use;
// - portable: under a random key that is wrapped with each admin's public
//   key. After a restore onto another server the runtime copy is useless,
//   and an admin's client unwraps the portable one to repair the settings.
// Backup archives carry the portable copy only.

const VERSION = 3;
const CONTEXT = 'backup.settings';

// The portable copy as the web vault opens it: AES-256-GCM, base64.
interface Encrypted {
  iv: string;
  ciphertext: string;
}

export interface PortableSettings extends Encrypted {
  wraps: Array<{ userId: string; wrappedKey: string }>;
}

interface Envelope {
  version: typeof VERSION;
  // Null in archives, and after a restore until an admin repairs the settings.
  runtime: SealedSecret | null;
  portable: PortableSettings;
}

function encrypt(plaintext: string, key: Buffer): Encrypted {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64') };
}

function parseEnvelope(raw: string): Envelope | null {
  try {
    const value = JSON.parse(raw) as Envelope;
    const portable = value?.portable;
    if (value?.version !== VERSION || (value.runtime !== null && typeof value.runtime !== 'string')) return null;
    if (typeof portable?.iv !== 'string' || typeof portable.ciphertext !== 'string' || !Array.isArray(portable.wraps)) return null;
    return value;
  } catch {
    return null;
  }
}

export function sealSettings(plaintext: string, secrets: SecretBox, users: User[]): string {
  const dek = randomBytes(32);
  const wraps: PortableSettings['wraps'] = [];
  for (const user of users) {
    if (user.role !== 'admin' || user.status !== 'active' || !user.publicKey) continue;
    try {
      const key = createPublicKey({ key: Buffer.from(user.publicKey, 'base64'), format: 'der', type: 'spki' });
      const wrapped = publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, dek);
      wraps.push({ userId: user.id, wrappedKey: wrapped.toString('base64') });
    } catch {
      // An unusable public key leaves that admin out of the portable copy.
    }
  }
  const envelope: Envelope = {
    version: VERSION,
    runtime: secrets.seal(plaintext, CONTEXT),
    portable: { ...encrypt(plaintext, dek), wraps },
  };
  return JSON.stringify(envelope);
}

// The settings, or null when this server cannot read them: they were
// encrypted elsewhere and need an admin to repair them.
export function openSettings(raw: string, secrets: SecretBox): string | null {
  const envelope = parseEnvelope(raw);
  if (!envelope?.runtime) return null;
  try {
    return secrets.open(envelope.runtime, CONTEXT);
  } catch {
    return null;
  }
}

export function portableSettings(raw: string): PortableSettings | null {
  return parseEnvelope(raw)?.portable ?? null;
}

// The envelope as it goes into a backup archive.
export function portableOnly(raw: string): string | null {
  const envelope = parseEnvelope(raw);
  if (!envelope) return null;
  const exported: Envelope = { version: VERSION, runtime: null, portable: envelope.portable };
  return JSON.stringify(exported);
}
