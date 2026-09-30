import { pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
import { badRequest } from '../../http/errors';
import { constantTimeEqual } from '../../platform/crypto';
import type { User } from '../../types';

// Clients never send the master password, only a hash of it (600k PBKDF2
// rounds on the client). The server hashes that again before storing it, so
// a copy of the database cannot be replayed as a login.

const ITERATIONS = 100_000;
const PREFIX = '$s$';
const derive = promisify(pbkdf2);

export async function hashMasterPassword(clientHash: string, email: string): Promise<string> {
  const salt = Buffer.from(email.trim().toLowerCase(), 'utf8');
  const bits = await derive(Buffer.from(clientHash, 'utf8'), salt, ITERATIONS, 32, 'sha256');
  return PREFIX + bits.toString('base64');
}

export async function verifyMasterPassword(
  user: Pick<User, 'email' | 'masterPasswordHash'>,
  clientHash: string | null | undefined,
): Promise<boolean> {
  const given = clientHash?.trim();
  if (!given || !user.masterPasswordHash.startsWith(PREFIX)) return false;
  return constantTimeEqual(await hashMasterPassword(given, user.email), user.masterPasswordHash);
}

// Settings changes are confirmed with the master password.
export async function requireMasterPassword(
  user: Pick<User, 'email' | 'masterPasswordHash'>,
  clientHash: string | null | undefined,
): Promise<void> {
  if (!clientHash?.trim()) throw badRequest('masterPasswordHash is required');
  if (!(await verifyMasterPassword(user, clientHash))) throw badRequest('Invalid password');
}
