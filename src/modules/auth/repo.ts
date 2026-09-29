import type { Executor } from '../../platform/db';
import type { NewRow, Row } from '../../platform/db/schema';
import type { Device, User } from '../../types';
import { toUser } from '../accounts/rows';
import { toDevice } from '../devices/rows';

// The user a token names and, when it was issued to a device, that device.
// Access tokens name the device by its identifier, refresh tokens by its id.
export async function findSession(
  db: Executor,
  userId: string,
  device: { id: string } | { identifier: string } | null,
): Promise<{ user: User; device: Device | null } | null> {
  const [user, deviceRow] = await Promise.all([
    db.selectFrom('users').selectAll().where('id', '=', userId).executeTakeFirst(),
    device
      ? db
          .selectFrom('devices')
          .selectAll()
          .where('user_id', '=', userId)
          .where((eb) => ('id' in device ? eb('id', '=', device.id) : eb('identifier', '=', device.identifier)))
          .executeTakeFirst()
      : undefined,
  ]);
  if (!user) return null;
  return { user: toUser(user), device: deviceRow ? toDevice(deviceRow) : null };
}

// Refresh tokens are stored under a hash of the token, never the token.

export type RefreshTokenRow = Row<'refresh_tokens'>;

export function findRefreshToken(db: Executor, hash: Buffer): Promise<RefreshTokenRow | undefined> {
  return db.selectFrom('refresh_tokens').selectAll().where('token_hash', '=', hash).executeTakeFirst();
}

export async function insertRefreshToken(db: Executor, row: NewRow<'refresh_tokens'>): Promise<void> {
  await db.insertInto('refresh_tokens').values(row).execute();
}

// Marks a token as replaced. False when another request replaced it first.
export async function markRefreshTokenRotated(db: Executor, hash: Buffer, now: string): Promise<boolean> {
  const result = await db
    .updateTable('refresh_tokens')
    .set({ rotated_at: now, last_used_at: now })
    .where('token_hash', '=', hash)
    .where('rotated_at', 'is', null)
    .executeTakeFirst();
  return result.numUpdatedRows > 0n;
}

export async function deleteRefreshToken(db: Executor, hash: Buffer): Promise<void> {
  await db.deleteFrom('refresh_tokens').where('token_hash', '=', hash).execute();
}

export async function deleteRefreshTokenFamily(db: Executor, familyId: string): Promise<void> {
  await db.deleteFrom('refresh_tokens').where('family_id', '=', familyId).execute();
}

// All the user's tokens, or those of one device. Returns how many families
// (sessions) there were.
export async function deleteUserRefreshTokens(db: Executor, userId: string, deviceIdentifier?: string): Promise<number> {
  let query = db.deleteFrom('refresh_tokens').where('user_id', '=', userId);
  if (deviceIdentifier !== undefined) {
    query = query.where('device_id', 'in', (eb) =>
      eb.selectFrom('devices').select('id').where('user_id', '=', userId).where('identifier', '=', deviceIdentifier),
    );
  }
  const rows = await query.returning('family_id').execute();
  return new Set(rows.map((row) => row.family_id)).size;
}
