import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import type { Device } from '../../types';
import { toDevice } from './rows';

export async function findDevice(db: Executor, userId: string, identifier: string): Promise<Device | null> {
  const row = await db
    .selectFrom('devices')
    .selectAll()
    .where('user_id', '=', userId)
    .where('device_identifier', '=', identifier)
    .executeTakeFirst();
  return row ? toDevice(row) : null;
}

// Records a sign-in from a device. A device keeps its session stamp and
// push id across sign-ins; a new one gets fresh ones.
export async function saveSignedInDevice(
  db: Executor,
  userId: string,
  device: { identifier: string; name: string; type: number },
): Promise<Device> {
  const now = new Date().toISOString();
  const row = await db
    .insertInto('devices')
    .values({
      user_id: userId,
      device_identifier: device.identifier,
      name: device.name,
      type: device.type,
      session_stamp: randomUUID(),
      push_uuid: randomUUID(),
      banned: 0,
      last_seen_at: now,
      created_at: now,
      updated_at: now,
    })
    .onConflict((oc) =>
      oc.columns(['user_id', 'device_identifier']).doUpdateSet({
        name: (eb) => eb.ref('excluded.name'),
        type: (eb) => eb.ref('excluded.type'),
        session_stamp: sql`COALESCE(NULLIF(devices.session_stamp, ''), excluded.session_stamp)`,
        push_uuid: sql`COALESCE(devices.push_uuid, excluded.push_uuid)`,
        last_seen_at: now,
        updated_at: now,
      }),
    )
    .returningAll()
    .executeTakeFirstOrThrow();
  return toDevice(row);
}

export async function setDevicePushToken(db: Executor, userId: string, identifier: string, pushToken: string): Promise<void> {
  await db
    .updateTable('devices')
    .set({ push_token: pushToken, updated_at: new Date().toISOString() })
    .where('user_id', '=', userId)
    .where('device_identifier', '=', identifier)
    .execute();
}

export async function touchDevice(db: Executor, userId: string, identifier: string): Promise<void> {
  await db
    .updateTable('devices')
    .set({ last_seen_at: new Date().toISOString() })
    .where('user_id', '=', userId)
    .where('device_identifier', '=', identifier)
    .execute();
}
