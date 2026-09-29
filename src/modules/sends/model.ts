import { pbkdf2, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { base64url, constantTimeEqual, fromBase64url } from '../../platform/crypto';

// A Send shares a text or a file with anyone who has its link. Its name,
// notes, text and file name are encrypted with a key that only the link
// carries.

export const SendType = { Text: 0, File: 1 } as const;
export type SendType = (typeof SendType)[keyof typeof SendType];

export const SendAuthType = { Email: 0, Password: 1, None: 2 } as const;

export interface SendText {
  text: string | null;
  hidden: boolean;
}

export interface SendFile {
  id: string;
  fileName: string;
  size: number;
  sizeName: string;
}

// Clients send a hash of the Send password, stretched with the Send key.
// The server keeps a salted hash of that.
export interface SendPassword {
  hash: string;
  salt: string;
  iterations: number;
}

export interface Send {
  id: string;
  userId: string;
  type: SendType;
  name: string;
  notes: string | null;
  // The Send key, encrypted with the owner's key.
  key: string;
  text: SendText | null;
  file: SendFile | null;
  password: SendPassword | null;
  maxAccessCount: number | null;
  accessCount: number;
  disabled: boolean;
  hideEmail: boolean;
  createdAt: string;
  updatedAt: string;
  expirationDate: string | null;
  deletionDate: string;
}

const PASSWORD_ITERATIONS = 100_000;

const pbkdf2Async = promisify(pbkdf2);
const derive = (password: string, salt: Buffer, iterations: number) => pbkdf2Async(password, salt, iterations, 32, 'sha256');

export async function hashSendPassword(password: string): Promise<SendPassword> {
  const salt = randomBytes(32);
  const hash = await derive(password, salt, PASSWORD_ITERATIONS);
  return { hash: base64url(hash), salt: base64url(salt), iterations: PASSWORD_ITERATIONS };
}

export async function checkSendPassword(stored: SendPassword, password: string): Promise<boolean> {
  const expected = fromBase64url(stored.hash);
  const salt = fromBase64url(stored.salt);
  if (!expected || !salt || !password) return false;
  return constantTimeEqual(await derive(password, salt, stored.iterations), expected);
}

// Whether recipients can open it now.
export function isAvailable(send: Send, now = Date.now()): boolean {
  if (send.disabled) return false;
  if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) return false;
  if (send.expirationDate && Date.parse(send.expirationDate) <= now) return false;
  return Date.parse(send.deletionDate) > now;
}

// The id in Send links: the 16 bytes of the Send id, base64url-encoded.
export const accessIdOf = (id: string) => base64url(Buffer.from(id.replace(/-/g, ''), 'hex'));

export function sendIdOf(accessId: string): string | null {
  const bytes = fromBase64url(accessId);
  if (!bytes || bytes.length !== 16) return null;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
