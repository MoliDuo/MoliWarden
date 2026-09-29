import { constants, createCipheriv, createDecipheriv, createPublicKey, hkdfSync, publicEncrypt, randomBytes } from 'node:crypto';
import type { User } from '../../types';

// Backup settings hold the destinations' credentials, so they are stored
// encrypted, twice:
// - runtime: under a key derived from JWT_SECRET, for this server's own use;
// - portable: under a random key that is wrapped with each admin's public
//   key. After a restore onto another server the runtime copy is useless,
//   and an admin's client unwraps the portable one to repair the settings.
// Backup archives carry the portable copy only.

// Wire constants of the stored envelope; renamed with the 3.3 migration.
const RUNTIME_SALT = 'nodewarden.backup-settings.runtime.v2';
const RUNTIME_INFO = 'runtime';

interface Sealed {
  iv: string;
  ciphertext: string;
}

export interface PortableSettings extends Sealed {
  wraps: Array<{ userId: string; wrappedKey: string }>;
}

interface Envelope {
  version: 2;
  portableOnly?: true;
  runtime: Sealed;
  portable: PortableSettings;
}

function seal(plaintext: string, key: Buffer): Sealed {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString('base64'), ciphertext: ciphertext.toString('base64') };
}

function open(sealed: Sealed, key: Buffer): string {
  const iv = Buffer.from(sealed.iv, 'base64');
  const body = Buffer.from(sealed.ciphertext, 'base64');
  if (iv.length !== 12 || body.length < 16) throw new Error('Backup settings envelope is invalid');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(body.subarray(body.length - 16));
  return Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]).toString('utf8');
}

const runtimeKey = (jwtSecret: string) => Buffer.from(hkdfSync('sha256', jwtSecret, RUNTIME_SALT, RUNTIME_INFO, 32));

function parseEnvelope(raw: string): Envelope | null {
  try {
    const value = JSON.parse(raw) as Envelope;
    const sealed = (part: Partial<Sealed> | undefined) => typeof part?.iv === 'string' && typeof part.ciphertext === 'string';
    if (value?.version !== 2 || !sealed(value.runtime) || !sealed(value.portable) || !Array.isArray(value.portable.wraps)) return null;
    return value;
  } catch {
    return null;
  }
}

export function sealSettings(plaintext: string, jwtSecret: string, users: User[]): string {
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
    version: 2,
    runtime: seal(plaintext, runtimeKey(jwtSecret)),
    portable: { ...seal(plaintext, dek), wraps },
  };
  return JSON.stringify(envelope);
}

// The settings, or null when this server cannot read them: they were
// encrypted elsewhere and need an admin to repair them.
export function openSettings(raw: string, jwtSecret: string): string | null {
  const envelope = parseEnvelope(raw);
  if (!envelope || envelope.portableOnly) return null;
  try {
    return open(envelope.runtime, runtimeKey(jwtSecret));
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
  const exported: Envelope = { version: 2, portableOnly: true, runtime: { iv: '', ciphertext: '' }, portable: envelope.portable };
  return JSON.stringify(exported);
}
