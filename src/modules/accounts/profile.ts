import type { ProfileResponse, User } from '../../types';
import { buildAccountKeys } from './decryption';

// The organizations section of a profile: `organizations` lists the ones
// the user holds the key of, `organizationsNew` also those still awaiting
// confirmation.
export interface ProfileOrganizations {
  organizations: Record<string, unknown>[];
  organizationsNew: Record<string, unknown>[];
}

export interface ProfileExtras {
  organizations: ProfileOrganizations;
  twoFactorEnabled: boolean;
  yubikeyEnabled: boolean;
}

export function profileJson(user: User, extras: ProfileExtras): ProfileResponse {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: extras.twoFactorEnabled,
    yubikeyEnabled: extras.yubikeyEnabled,
    key: user.key,
    privateKey: user.privateKey,
    accountKeys: buildAccountKeys(user),
    securityStamp: user.securityStamp,
    organizations: extras.organizations.organizations,
    organizationsNew: extras.organizations.organizationsNew,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    // New-device verification sends codes by email, which this server cannot.
    verifyDevices: false,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}
