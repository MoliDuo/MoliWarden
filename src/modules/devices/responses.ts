import { withPascalCase } from '../../http/casing';
import type { Device } from '../../types';

// Devices as official clients read them, in both casings. The identifier
// the client chose doubles as the device's id.

const displayName = (device: Device) => device.deviceNote?.trim() || device.name;
const isTrusted = (device: Device) => !!(device.encryptedUserKey && device.encryptedPublicKey);

export function deviceJson(device: Device) {
  return {
    ...withPascalCase({
      id: device.deviceIdentifier,
      userId: device.userId,
      name: displayName(device),
      systemName: device.name,
      deviceNote: device.deviceNote,
      identifier: device.deviceIdentifier,
      type: device.type,
      creationDate: device.createdAt,
      revisionDate: device.updatedAt,
      lastActivityDate: device.lastSeenAt,
      lastSeenAt: device.lastSeenAt,
      hasStoredDevice: true,
      isTrusted: isTrusted(device),
      encryptedUserKey: device.encryptedUserKey,
      encryptedPublicKey: device.encryptedPublicKey,
      // Login requests are listed under /auth-requests/pending instead.
      devicePendingAuthRequest: null,
    }),
    object: 'device',
  };
}

// A device's keys, handed to the device itself after sign-in.
export function protectedDeviceJson(device: Device) {
  return {
    ...withPascalCase({
      id: device.deviceIdentifier,
      name: displayName(device),
      systemName: device.name,
      deviceNote: device.deviceNote,
      identifier: device.deviceIdentifier,
      type: device.type,
      creationDate: device.createdAt,
      encryptedUserKey: device.encryptedUserKey,
      encryptedPublicKey: device.encryptedPublicKey,
    }),
    object: 'protectedDevice',
  };
}
