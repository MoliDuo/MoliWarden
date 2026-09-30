import type { Row } from '../../platform/db/schema';
import type { Device } from '../../types';

export function toDevice(row: Row<'devices'>): Device {
  return {
    id: row.id,
    userId: row.user_id,
    deviceIdentifier: row.identifier,
    name: row.name,
    deviceNote: row.note,
    type: row.type,
    sessionStamp: row.session_stamp,
    encryptedUserKey: row.encrypted_user_key,
    encryptedPublicKey: row.encrypted_public_key,
    encryptedPrivateKey: row.encrypted_private_key,
    pushUuid: row.push_uuid,
    pushToken: row.push_token,
    lastSeenAt: row.last_seen_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
