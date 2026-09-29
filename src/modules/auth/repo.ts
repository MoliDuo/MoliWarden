import { jsonObjectFrom } from 'kysely/helpers/postgres';
import type { Executor } from '../../platform/db';
import type { Row } from '../../platform/db/schema';
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
