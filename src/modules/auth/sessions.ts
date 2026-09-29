import { randomUUID } from 'node:crypto';
import { getRefreshTokenSlidingTtlMs, LIMITS } from '../../config/limits';
import { randomToken, sha256Hex } from '../../platform/crypto';
import type { Db, Executor } from '../../platform/db';
import type { Device, User } from '../../types';
import {
  deleteRefreshToken,
  deleteRefreshTokenFamily,
  deleteUserRefreshTokens,
  findRefreshToken,
  findSession,
  insertRefreshToken,
  markRefreshTokenRotated,
  type RefreshTokenRow,
} from './repo';

// A session is what a refresh token keeps alive. Refresh tokens are single
// use: every refresh hands out a new token of the same family. A replaced
// token still works for a minute, for clients that sent two refreshes at
// once or lost the response; after that, presenting it again means it was
// copied, and the whole family is revoked.

// How long a token keeps working after it was replaced.
const REUSE_GRACE_MS = 60_000;

// Who holds the session; decides how long it may sit unused.
export type ClientType = 'web' | 'mobile' | 'browser' | 'desktop' | 'cli' | 'other';

export type SessionEndReason =
  | 'unknown'
  | 'expired'
  | 'reused'
  | 'user_inactive'
  | 'security_stamp_changed'
  | 'device_logged_out';

export type RefreshResult =
  | { ok: true; user: User; device: Device | null; refreshToken: string }
  | { ok: false; reason: SessionEndReason; userId: string | null };

const storageKey = (token: string) => `sha256:${sha256Hex(token)}`;

function newRow(
  user: Pick<User, 'id' | 'securityStamp'>,
  device: Pick<Device, 'deviceIdentifier' | 'sessionStamp'> | null,
  clientType: string,
  familyId: string,
  absoluteExpiresAt: number,
  now: number,
): { token: string; row: RefreshTokenRow } {
  const token = randomToken(LIMITS.auth.refreshTokenRandomBytes);
  return {
    token,
    row: {
      token: storageKey(token),
      user_id: user.id,
      expires_at: Math.min(now + getRefreshTokenSlidingTtlMs(clientType), absoluteExpiresAt),
      absolute_expires_at: absoluteExpiresAt,
      device_identifier: device?.deviceIdentifier ?? null,
      device_session_stamp: device?.sessionStamp ?? null,
      security_stamp: user.securityStamp,
      client_type: clientType,
      family_id: familyId,
      created_at: now,
      last_used_at: now,
      rotated_at: null,
    },
  };
}

export async function startSession(
  db: Executor,
  user: Pick<User, 'id' | 'securityStamp'>,
  device: Pick<Device, 'deviceIdentifier' | 'sessionStamp'> | null,
  clientType: ClientType,
  now = Date.now(),
): Promise<string> {
  const { token, row } = newRow(user, device, clientType, randomUUID(), now + LIMITS.auth.refreshTokenAbsoluteTtlMs, now);
  await insertRefreshToken(db, row);
  return token;
}

export async function refreshSession(db: Db, token: string, now = Date.now()): Promise<RefreshResult> {
  const key = storageKey(token);
  const row = await findRefreshToken(db, key);
  if (!row) return { ok: false, reason: 'unknown', userId: null };
  const fail = async (reason: SessionEndReason, revoke: () => Promise<void>): Promise<RefreshResult> => {
    await revoke();
    return { ok: false, reason, userId: row.user_id };
  };
  const familyId = row.family_id ?? randomUUID();
  const revokeToken = () => deleteRefreshToken(db, key);
  const revokeFamily = () => (row.family_id ? deleteRefreshTokenFamily(db, row.family_id) : revokeToken());

  if (row.expires_at < now || (row.absolute_expires_at !== null && row.absolute_expires_at < now)) {
    return fail('expired', revokeToken);
  }
  if (row.rotated_at !== null && now - row.rotated_at > REUSE_GRACE_MS) return fail('reused', revokeFamily);

  const session = await findSession(db, row.user_id, row.device_identifier);
  if (!session || session.user.status !== 'active') return fail('user_inactive', revokeFamily);
  if (session.user.securityStamp !== row.security_stamp) return fail('security_stamp_changed', revokeFamily);
  if (row.device_identifier && session.device?.sessionStamp !== row.device_session_stamp) {
    return fail('device_logged_out', revokeFamily);
  }

  const absoluteExpiresAt = row.absolute_expires_at ?? now + LIMITS.auth.refreshTokenAbsoluteTtlMs;
  const next = newRow(session.user, session.device, row.client_type ?? 'other', familyId, absoluteExpiresAt, now);
  await db.transaction().execute(async (tx) => {
    // Losing this race means a parallel refresh just replaced the token,
    // which the grace period allows.
    await markRefreshTokenRotated(tx, key, familyId, now);
    await insertRefreshToken(tx, next.row);
  });
  return { ok: true, user: session.user, device: session.device, refreshToken: next.token };
}

// Logs out the session a refresh token belongs to. Unknown tokens are ignored.
export async function revokeSession(db: Executor, token: string): Promise<void> {
  const key = storageKey(token);
  const row = await findRefreshToken(db, key);
  if (row?.family_id) await deleteRefreshTokenFamily(db, row.family_id);
  else if (row) await deleteRefreshToken(db, key);
}

// Ends every session of the user, or of one of their devices, once the
// access tokens expire. Returns how many sessions there were.
export function endAllSessions(db: Executor, userId: string, deviceIdentifier?: string): Promise<number> {
  return deleteUserRefreshTokens(db, userId, deviceIdentifier);
}
