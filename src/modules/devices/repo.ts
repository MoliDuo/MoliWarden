import { randomUUID } from 'node:crypto';
import { sql, type UpdateObject } from 'kysely';
import type { Executor } from '../../platform/db';
import type { Database } from '../../platform/db/schema';
import type { Device } from '../../types';
import { toDevice } from './rows';

// The keys a trusted device keeps the user key under. A missing key is
// left as it is; null removes it.
export interface DeviceKeys {
  encryptedUserKey?: string | null;
  encryptedPublicKey?: string | null;
  encryptedPrivateKey?: string | null;
}

const keyColumns = (keys: DeviceKeys) => ({
  ...(keys.encryptedUserKey !== undefined ? { encrypted_user_key: keys.encryptedUserKey } : {}),
  ...(keys.encryptedPublicKey !== undefined ? { encrypted_public_key: keys.encryptedPublicKey } : {}),
  ...(keys.encryptedPrivateKey !== undefined ? { encrypted_private_key: keys.encryptedPrivateKey } : {}),
});

export async function findDevice(db: Executor, userId: string, identifier: string): Promise<Device | null> {
  const row = await db
    .selectFrom('devices')
    .selectAll()
    .where('user_id', '=', userId)
    .where('device_identifier', '=', identifier)
    .executeTakeFirst();
  return row ? toDevice(row) : null;
}

// Most recently used first.
export async function listDevices(db: Executor, userId: string): Promise<Device[]> {
  const rows = await db
    .selectFrom('devices')
    .selectAll()
    .where('user_id', '=', userId)
    .orderBy(sql`COALESCE(last_seen_at, created_at)`, 'desc')
    .orderBy('updated_at', 'desc')
    .execute();
  return rows.map(toDevice);
}

export async function isKnownDevice(db: Executor, email: string, identifier: string): Promise<boolean> {
  const row = await db
    .selectFrom('devices')
    .innerJoin('users', 'users.id', 'devices.user_id')
    .select('devices.device_identifier')
    .where('users.email', '=', email)
    .where('devices.device_identifier', '=', identifier)
    .executeTakeFirst();
  return !!row;
}

// Records a device the user signed in on, or that registered itself. A
// device keeps its session stamp, push id and keys across sign-ins; a new
// one gets fresh ones.
export async function saveDevice(
  db: Executor,
  userId: string,
  device: { identifier: string; name: string; type: number; keys?: DeviceKeys },
): Promise<Device> {
  const now = new Date().toISOString();
  const keys = keyColumns(device.keys ?? {});
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
      ...keys,
    })
    .onConflict((oc) =>
      oc.columns(['user_id', 'device_identifier']).doUpdateSet({
        name: (eb) => eb.ref('excluded.name'),
        type: (eb) => eb.ref('excluded.type'),
        session_stamp: sql`COALESCE(NULLIF(devices.session_stamp, ''), excluded.session_stamp)`,
        push_uuid: sql`COALESCE(devices.push_uuid, excluded.push_uuid)`,
        last_seen_at: now,
        updated_at: now,
        ...keys,
      }),
    )
    .returningAll()
    .executeTakeFirstOrThrow();
  return toDevice(row);
}

async function updateDevice(
  db: Executor,
  userId: string,
  identifier: string,
  changes: UpdateObject<Database, 'devices'>,
): Promise<Device | null> {
  const row = await db
    .updateTable('devices')
    .set(changes)
    .where('user_id', '=', userId)
    .where('device_identifier', '=', identifier)
    .returningAll()
    .executeTakeFirst();
  return row ? toDevice(row) : null;
}

export function setDeviceKeys(db: Executor, userId: string, identifier: string, keys: DeviceKeys): Promise<Device | null> {
  return updateDevice(db, userId, identifier, { ...keyColumns(keys), updated_at: new Date().toISOString() });
}

// The note the user gave the device, shown in place of its name.
export function setDeviceNote(db: Executor, userId: string, identifier: string, note: string): Promise<Device | null> {
  return updateDevice(db, userId, identifier, { device_note: note, updated_at: new Date().toISOString() });
}

// Devices from before push ids existed get one here.
export function setDevicePushToken(db: Executor, userId: string, identifier: string, pushToken: string): Promise<Device | null> {
  return updateDevice(db, userId, identifier, {
    push_token: pushToken,
    push_uuid: sql`COALESCE(push_uuid, ${randomUUID()})`,
    updated_at: new Date().toISOString(),
  });
}

// Returns the device as it was, so its push registration can be removed.
export async function clearDevicePushToken(db: Executor, userId: string, identifier: string): Promise<Device | null> {
  const before = await findDevice(db, userId, identifier);
  if (!before?.pushToken) return null;
  await updateDevice(db, userId, identifier, { push_token: null, updated_at: new Date().toISOString() });
  return before;
}

export async function clearDeviceKeys(db: Executor, userId: string, identifiers: string[]): Promise<number> {
  if (!identifiers.length) return 0;
  const result = await db
    .updateTable('devices')
    .set({ encrypted_user_key: null, encrypted_public_key: null, encrypted_private_key: null, updated_at: new Date().toISOString() })
    .where('user_id', '=', userId)
    .where('device_identifier', 'in', identifiers)
    .executeTakeFirst();
  return Number(result.numUpdatedRows);
}

export async function touchDevice(db: Executor, userId: string, identifier: string): Promise<void> {
  await updateDevice(db, userId, identifier, { last_seen_at: new Date().toISOString() });
}

export async function deleteDevice(db: Executor, userId: string, identifier: string): Promise<Device | null> {
  const row = await db
    .deleteFrom('devices')
    .where('user_id', '=', userId)
    .where('device_identifier', '=', identifier)
    .returningAll()
    .executeTakeFirst();
  return row ? toDevice(row) : null;
}

export async function deleteUserDevices(db: Executor, userId: string): Promise<Device[]> {
  const rows = await db.deleteFrom('devices').where('user_id', '=', userId).returningAll().execute();
  return rows.map(toDevice);
}
