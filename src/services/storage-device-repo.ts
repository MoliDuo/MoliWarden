import type { Device } from '../types';

type TrustedTokenKeyFn = (token: string) => Promise<string>;

function mapDeviceRow(row: any): Device {
  return {
    userId: row.user_id,
    deviceIdentifier: row.device_identifier,
    name: row.name,
    deviceNote: row.device_note ?? null,
    type: row.type,
    sessionStamp: row.session_stamp || '',
    encryptedUserKey: row.encrypted_user_key ?? null,
    encryptedPublicKey: row.encrypted_public_key ?? null,
    encryptedPrivateKey: row.encrypted_private_key ?? null,
    pushUuid: row.push_uuid ?? null,
    pushToken: row.push_token ?? null,
    lastSeenAt: row.last_seen_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function rotateDeviceSessionStamp(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  sessionStamp: string
): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .prepare('UPDATE devices SET session_stamp = ?, updated_at = ? WHERE user_id = ? AND device_identifier = ?')
    .bind(sessionStamp, now, userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function getDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<Device | null> {
  const row = await db
    .prepare(
      'SELECT user_id, device_identifier, name, type, session_stamp, encrypted_user_key, encrypted_public_key, encrypted_private_key, push_uuid, push_token, banned, banned_at, device_note, last_seen_at, created_at, updated_at ' +
        'FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1'
    )
    .bind(userId, deviceIdentifier)
    .first<any>();
  return row ? mapDeviceRow(row) : null;
}

export async function getDevicePushUuid(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<string | null> {
  const row = await db
    .prepare('SELECT push_uuid FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
    .bind(userId, deviceIdentifier)
    .first<{ push_uuid: string | null }>();
  return row?.push_uuid ?? null;
}

export async function userHasPushDevice(db: D1Database, userId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT 1 FROM devices WHERE user_id = ? AND push_token IS NOT NULL AND push_token <> ? LIMIT 1')
    .bind(userId, '')
    .first<{ '1': number }>();
  return !!row;
}

export async function saveTrustedTwoFactorDeviceToken(
  db: D1Database,
  trustedTokenKey: TrustedTokenKeyFn,
  token: string,
  userId: string,
  deviceIdentifier: string,
  expiresAtMs: number
): Promise<void> {
  const tokenKey = await trustedTokenKey(token);
  await db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE expires_at < ?').bind(Date.now()).run();
  await db
    .prepare(
      'INSERT INTO trusted_two_factor_device_tokens(token, user_id, device_identifier, expires_at) VALUES(?, ?, ?, ?) ' +
        'ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, device_identifier=excluded.device_identifier, expires_at=excluded.expires_at'
    )
    .bind(tokenKey, userId, deviceIdentifier, expiresAtMs)
    .run();
}

export async function getTrustedTwoFactorDeviceTokenUserId(
  db: D1Database,
  trustedTokenKey: TrustedTokenKeyFn,
  token: string,
  deviceIdentifier: string
): Promise<string | null> {
  const now = Date.now();
  const tokenKey = await trustedTokenKey(token);
  const row = await db
    .prepare('SELECT user_id, expires_at FROM trusted_two_factor_device_tokens WHERE token = ? AND device_identifier = ?')
    .bind(tokenKey, deviceIdentifier)
    .first<{ user_id: string; expires_at: number }>();

  if (!row) return null;
  if (row.expires_at && row.expires_at < now) {
    await db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE token = ?').bind(tokenKey).run();
    return null;
  }
  return row.user_id;
}
