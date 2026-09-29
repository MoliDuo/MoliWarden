import { randomUUID } from 'node:crypto';
import { notFound, conflict } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Device, User } from '../../types';
import { updateUser } from '../accounts/repo';
import { recordAudit, requestMetadata, type AuditLevel } from '../audit/service';
import { requireMasterPassword } from '../auth/password';
import { endAllSessions } from '../auth/sessions';
import { deleteRememberTokens, extendRememberTokens, listRememberedDevices } from '../two-factor/repo';
import {
  clearDeviceKeys,
  clearDevicePushToken,
  deleteDevice,
  deleteUserDevices,
  findDevice,
  isKnownDevice,
  listDevices,
  saveDevice,
  setDeviceKeys,
  setDeviceNote,
  setDevicePushToken,
  type DeviceKeys,
} from './repo';
import { deviceJson, listJson, protectedDeviceJson } from './responses';
import type { RegisterDeviceInput, TrustInput } from './schemas';

// The devices a user is signed in on. A device may also be "remembered",
// skipping two-step login, and "trusted", holding the user key encrypted
// to a key of its own so it can unlock without the master password.

// "Trust permanently" in the web vault.
const PERMANENT_TRUST_UNTIL = Date.UTC(2099, 11, 31, 23, 59, 59);

const UNKNOWN_DEVICE_TYPE = 14;

function audit(
  deps: Deps,
  request: Request,
  user: User,
  action: string,
  target: { type: 'device' | 'user'; id: string },
  level: AuditLevel = 'security',
  metadata = {},
) {
  return recordAudit(deps.db, {
    actorUserId: user.id,
    action,
    category: 'device',
    level,
    targetType: target.type,
    targetId: target.id,
    metadata: { ...metadata, ...requestMetadata(request) },
  });
}

async function requireDevice(deps: Deps, user: User, identifier: string): Promise<Device> {
  const device = await findDevice(deps.db, user.id, identifier);
  if (!device) throw notFound('Device not found');
  return device;
}

// Asked before sign-in, so that a new device can be told to expect an
// email check. Never reveals whether the email has an account.
export function knownDevice(deps: Deps, email: string, identifier: string): Promise<boolean> {
  return email && identifier ? isKnownDevice(deps.db, email, identifier) : Promise.resolve(false);
}

export async function devicesJson(deps: Deps, user: User) {
  return listJson((await listDevices(deps.db, user.id)).map(deviceJson));
}

export async function deviceById(deps: Deps, user: User, identifier: string) {
  return deviceJson(await requireDevice(deps, user, identifier));
}

export async function deviceKeys(deps: Deps, user: User, identifier: string) {
  return protectedDeviceJson(await requireDevice(deps, user, identifier));
}

// The devices together with how long each skips two-step login, including
// remembered devices that have since been removed.
export async function authorizedDevices(deps: Deps, user: User) {
  const [devices, remembered] = await Promise.all([
    listDevices(deps.db, user.id),
    listRememberedDevices(deps.db, user.id, Date.now()),
  ]);
  const byIdentifier = new Map(remembered.map((entry) => [entry.identifier, entry]));
  const trust = (identifier: string) => {
    const entry = byIdentifier.get(identifier);
    return {
      online: false,
      trusted: !!entry,
      trustedTokenCount: entry?.tokenCount ?? 0,
      trustedUntil: entry ? new Date(entry.expiresAt).toISOString() : null,
    };
  };

  const known = new Set(devices.map((device) => device.deviceIdentifier));
  const removed = remembered
    .filter((entry) => !known.has(entry.identifier))
    .map((entry) => ({
      ...deviceJson({
        userId: user.id,
        deviceIdentifier: entry.identifier,
        name: 'Unknown device',
        type: UNKNOWN_DEVICE_TYPE,
        sessionStamp: '',
        encryptedUserKey: null,
        encryptedPublicKey: null,
        encryptedPrivateKey: null,
        pushUuid: null,
        pushToken: null,
        deviceNote: null,
        lastSeenAt: null,
        createdAt: '',
        updatedAt: '',
      }),
      isTrusted: true,
      hasStoredDevice: false,
      ...trust(entry.identifier),
    }));
  return listJson([...devices.map((device) => ({ ...deviceJson(device), ...trust(device.deviceIdentifier) })), ...removed]);
}

export async function registerDevice(deps: Deps, request: Request, user: User, input: RegisterDeviceInput) {
  let device = await saveDevice(deps.db, user.id, {
    identifier: input.identifier,
    name: input.name || 'Unknown device',
    type: input.type,
    keys: input,
  });
  if (input.pushToken) device = await setPushToken(deps, user, device.deviceIdentifier, input.pushToken);
  await audit(deps, request, user, 'device.register', { type: 'device', id: device.deviceIdentifier }, 'info');
  return deviceJson(device);
}

export async function renameDevice(deps: Deps, request: Request, user: User, identifier: string, name: string) {
  const device = await setDeviceNote(deps.db, user.id, identifier, name);
  if (!device) throw notFound('Device not found');
  await audit(deps, request, user, 'device.name.update', { type: 'device', id: identifier }, 'info', { name });
  return deviceJson(device);
}

export async function updateDeviceKeys(deps: Deps, user: User, identifier: string, keys: DeviceKeys) {
  const device = await setDeviceKeys(deps.db, user.id, identifier, keys);
  if (!device) throw notFound('Device not found');
  return deviceJson(device);
}

// After a user key rotation the client re-encrypts the new key for every
// trusted device, starting with the one it runs on.
export async function updateTrust(deps: Deps, user: User, current: Device | null, input: TrustInput) {
  const updates: Array<[string, DeviceKeys]> = (input.otherDevices ?? []).map(({ deviceId, ...keys }) => [deviceId, keys]);
  if (current && input.currentDevice) updates.unshift([current.deviceIdentifier, input.currentDevice]);
  let updated = 0;
  await deps.db.transaction().execute(async (tx) => {
    for (const [identifier, keys] of updates) {
      if (await setDeviceKeys(tx, user.id, identifier, keys)) updated += 1;
    }
  });
  return { success: true, updated };
}

// Stops devices from unlocking with their own keys and from skipping
// two-step login.
export async function untrustDevices(deps: Deps, request: Request, user: User, identifiers: string[]) {
  const removed = await deps.db.transaction().execute(async (tx) => {
    await deleteRememberTokens(tx, user.id, identifiers);
    return clearDeviceKeys(tx, user.id, identifiers);
  });
  await audit(deps, request, user, 'device.trust.revoke_batch', { type: 'user', id: user.id }, 'security', {
    requested: identifiers.length,
    removed,
  });
  return { success: true, removed };
}

// A client that expected to unlock with its device keys but got none.
export async function reportLostTrust(deps: Deps, request: Request, user: User, identifier: string) {
  await audit(deps, request, user, 'device.lost_trust', { type: 'device', id: identifier }, 'warn');
}

export async function forgetRemembered(deps: Deps, request: Request, user: User, identifier?: string) {
  const removed = await deleteRememberTokens(deps.db, user.id, identifier === undefined ? undefined : [identifier]);
  const target = identifier === undefined ? { type: 'user' as const, id: user.id } : { type: 'device' as const, id: identifier };
  await audit(deps, request, user, identifier === undefined ? 'device.trust.revoke_all' : 'device.trust.revoke', target, 'security', {
    removed,
  });
  return { success: true, removed };
}

export async function rememberPermanently(deps: Deps, request: Request, user: User, identifier: string) {
  const updated = await extendRememberTokens(deps.db, user.id, identifier, PERMANENT_TRUST_UNTIL, Date.now());
  if (!updated) throw conflict('Device is not currently trusted');
  await audit(deps, request, user, 'device.trust.permanent', { type: 'device', id: identifier }, 'security', { updated });
  return { success: true, updated, trustedUntil: new Date(PERMANENT_TRUST_UNTIL).toISOString() };
}

// Signs the device out: its sessions end and it is forgotten.
export async function removeDevice(
  deps: Deps,
  request: Request,
  user: User,
  identifier: string,
  action: 'device.delete' | 'device.deactivate',
) {
  const device = await deps.db.transaction().execute(async (tx) => {
    await deleteRememberTokens(tx, user.id, [identifier]);
    await endAllSessions(tx, user.id, identifier);
    return deleteDevice(tx, user.id, identifier);
  });
  if (device?.pushToken) deps.push.unregister(device.pushUuid);
  await audit(deps, request, user, action, { type: 'device', id: identifier }, 'security', { deleted: !!device });
  return { success: !!device };
}

// Signs out everywhere, this device included.
export async function removeAllDevices(deps: Deps, request: Request, user: User, secret: string) {
  await requireMasterPassword(user, secret);
  const result = await deps.db.transaction().execute(async (tx) => {
    const removedTrusted = await deleteRememberTokens(tx, user.id);
    const removedSessions = await endAllSessions(tx, user.id);
    const devices = await deleteUserDevices(tx, user.id);
    // Ends the access tokens already handed out.
    await updateUser(tx, user.id, { securityStamp: randomUUID() });
    return { removedTrusted, removedSessions, devices };
  });
  deps.push.signOut(
    user.id,
    result.devices.flatMap((device) => (device.pushToken && device.pushUuid ? [device.pushUuid] : [])),
  );
  const counts = {
    removedTrusted: result.removedTrusted,
    removedSessions: result.removedSessions,
    removedDevices: result.devices.length,
  };
  await audit(deps, request, user, 'device.delete_all', { type: 'user', id: user.id }, 'security', counts);
  return { success: true, ...counts };
}

// Mobile apps report the token their platform's push service gave them.
export async function setPushToken(deps: Deps, user: User, identifier: string, pushToken: string): Promise<Device> {
  const device = await setDevicePushToken(deps.db, user.id, identifier, pushToken);
  if (!device) throw notFound('Device not found');
  if (device.pushUuid) {
    deps.push.register({ userId: user.id, identifier, type: device.type, pushUuid: device.pushUuid, pushToken });
  }
  return device;
}

// Sent on logout.
export async function clearPushToken(deps: Deps, user: User, identifier: string): Promise<void> {
  const device = await clearDevicePushToken(deps.db, user.id, identifier);
  if (device) deps.push.unregister(device.pushUuid);
}
