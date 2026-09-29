import { jsonObjectFrom } from 'kysely/helpers/postgres';
import type { Executor } from '../../platform/db';
import type { NewRow, Row } from '../../platform/db/schema';
import type { Device, User } from '../../types';
import { toUser } from '../accounts/rows';
import { toDevice } from '../devices/rows';

// The user an access token names and, when it was issued to a device, that
// device, in one round trip.
export async function findSession(
  db: Executor,
  userId: string,
  deviceIdentifier: string | null,
): Promise<{ user: User; device: Device | null } | null> {
  const row = await db
    .selectFrom('users')
    .selectAll('users')
    .select((eb) =>
      jsonObjectFrom(
        eb
          .selectFrom('devices')
          .selectAll('devices')
          .whereRef('devices.user_id', '=', 'users.id')
          .where('devices.device_identifier', '=', deviceIdentifier ?? ''),
      ).as('device'),
    )
    .where('users.id', '=', userId)
    .executeTakeFirst();
  if (!row) return null;
  const { device, ...user } = row;
  return { user: toUser(user), device: device ? toDevice(device as Row<'devices'>) : null };
}

// Refresh tokens are stored under a hash of the token, never the token.

export type RefreshTokenRow = Row<'refresh_tokens'>;

export function findRefreshToken(db: Executor, key: string): Promise<RefreshTokenRow | undefined> {
  return db.selectFrom('refresh_tokens').selectAll().where('token', '=', key).executeTakeFirst();
}

export async function insertRefreshToken(db: Executor, row: NewRow<'refresh_tokens'>): Promise<void> {
  await db.insertInto('refresh_tokens').values(row).execute();
}

// Marks a token as replaced. False when another request replaced it first.
export async function markRefreshTokenRotated(db: Executor, key: string, familyId: string, now: number): Promise<boolean> {
  const result = await db
    .updateTable('refresh_tokens')
    .set({ rotated_at: now, family_id: familyId, last_used_at: now })
    .where('token', '=', key)
    .where('rotated_at', 'is', null)
    .executeTakeFirst();
  return result.numUpdatedRows > 0n;
}

export async function deleteRefreshToken(db: Executor, key: string): Promise<void> {
  await db.deleteFrom('refresh_tokens').where('token', '=', key).execute();
}

export async function deleteRefreshTokenFamily(db: Executor, familyId: string): Promise<void> {
  await db.deleteFrom('refresh_tokens').where('family_id', '=', familyId).execute();
}

export async function deleteUserRefreshTokens(db: Executor, userId: string): Promise<void> {
  await db.deleteFrom('refresh_tokens').where('user_id', '=', userId).execute();
}
