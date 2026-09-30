import type { Sealed } from '../platform/crypto';

export type UserRole = 'admin' | 'user';
export type UserStatus = 'active' | 'banned';

export interface User {
  id: string;
  email: string;
  name: string | null;
  masterPasswordHint: string | null;
  masterPasswordHash: string;
  key: string;
  privateKey: string | null;
  publicKey: string | null;
  kdfType: number;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  securityStamp: string;
  role: UserRole;
  status: UserStatus;
  verifyDevices?: boolean;
  // Turns two-step login off when every second factor is lost.
  // Both sealed with ENCRYPTION_KEY.
  recoveryCode: Sealed | null;
  apiKey: Sealed | null;
  keyId?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CustomEquivalentDomain {
  id: string;
  domains: string[];
  excluded: boolean;
}

export interface GlobalEquivalentDomain {
  type: number;
  domains: string[];
  excluded: boolean;
  [key: string]: unknown;
}

export interface DomainRulesResponse {
  equivalentDomains: string[][];
  customEquivalentDomains: CustomEquivalentDomain[];
  globalEquivalentDomains: GlobalEquivalentDomain[];
  object: 'domains';
}

export interface Device {
  // Ours; clients know a device by its identifier.
  id: string;
  userId: string;
  deviceIdentifier: string;
  name: string;
  deviceNote: string | null;
  type: number;
  sessionStamp: string;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  encryptedPrivateKey: string | null;
  pushUuid: string;
  pushToken: string | null;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type AccountPasskeyPrfStatus = 0 | 1 | 2;

export interface AccountPasskeyCredential {
  id: string;
  userId: string;
  purpose: 'login' | 'twoFactor';
  name: string;
  publicKey: string;
  credentialId: string;
  counter: number;
  type: string | null;
  aaGuid: string | null;
  transports: string[] | null;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  encryptedPrivateKey: string | null;
  supportsPrf: boolean;
  createdAt: string;
  updatedAt: string;
}

export type AccountPasskeyChallengeScope =
  | 'Authentication'
  | 'CreateCredential'
  | 'UpdateKeySet'
  | 'TwoFactorAuthentication'
  | 'TwoFactorCreate';

// UserDecryptionOptions types for mobile client compatibility
export interface MasterPasswordUnlockKdf {
  KdfType: number;
  Iterations: number;
  Memory: number | null;
  Parallelism: number | null;
}

export interface MasterPasswordUnlock {
  Kdf: MasterPasswordUnlockKdf;
  MasterKeyEncryptedUserKey: string;
  MasterKeyWrappedUserKey: string;
  Salt: string;
  Object: string;
}

export interface WebAuthnPrfDecryptionOption {
  EncryptedPrivateKey: string;
  EncryptedUserKey: string;
  CredentialId: string;
  Transports: string[];
  Object?: string;
}

export interface UserDecryptionOptions {
  HasMasterPassword: boolean;
  Object: string;
  // Bitwarden Android 2026.1.x expects this to exist; missing it breaks unlock when the vault is empty.
  MasterPasswordUnlock: MasterPasswordUnlock;
  TrustedDeviceOption: null;
  KeyConnectorOption: null;
  WebAuthnPrfOption?: WebAuthnPrfDecryptionOption | null;
}

export interface ProfileResponse {
  id: string;
  name: string | null;
  email: string;
  emailVerified: boolean;
  premium: boolean;
  premiumFromOrganization: boolean;
  usesKeyConnector: boolean;
  masterPasswordHint: string | null;
  culture: string;
  twoFactorEnabled: boolean;
  yubikeyEnabled?: boolean;
  key: string;
  privateKey: string | null;
  accountKeys: any | null;
  securityStamp: string;
  organizations: any[];
  organizationsNew?: any[];
  providers: any[];
  providerOrganizations: any[];
  forcePasswordReset: boolean;
  avatarColor: string | null;
  creationDate: string;
  verifyDevices: boolean;
  role?: UserRole;
  status?: UserStatus;
  object: string;
}
