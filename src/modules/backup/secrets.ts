import { badRequest } from '../../http/errors';
import type { Sealed, SecretBox } from '../../platform/crypto';
import { TOTP, YUBICO_CREDENTIALS } from '../two-factor/repo';
import {
  openRecoveryCode,
  openTotpSecret,
  openYubicoSecret,
  sealRecoveryCode,
  sealTotpSecret,
  sealYubicoSecret,
} from '../two-factor/secrets';
import type { Snapshot, VaultRecord } from './archive';

// The server seals some secrets with ENCRYPTION_KEY: recovery codes, TOTP
// seeds and the Yubico API key. Archives carry them in the clear, so a
// backup restores onto a server with another key; the rest of an archive
// is no less sensitive (it holds every login's password hash).
// API keys are not backed up at all: they can be issued again.

type Transform = {
  recoveryCode(userId: string, value: string): string;
  totpSecret(userId: string, value: string): string;
  yubicoSecret(value: string): string;
};

function text(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value) throw badRequest(`Invalid backup: ${what} is malformed`);
  return value;
}

function transform(snapshot: Snapshot, apply: Transform): Snapshot {
  const users = snapshot.users.map((user): VaultRecord => {
    if (user.recoveryCode === null || user.recoveryCode === undefined) return user;
    return { ...user, recoveryCode: apply.recoveryCode(text(user.id, 'a user id'), text(user.recoveryCode, 'a recovery code')) };
  });
  const twoFactorProviders = snapshot.twoFactorProviders.map((provider): VaultRecord => {
    if (provider.type !== TOTP) return provider;
    const data = provider.data as Record<string, unknown>;
    const secret = apply.totpSecret(text(provider.userId, 'a user id'), text(data.secret, 'a TOTP secret'));
    return { ...provider, data: { ...data, secret } };
  });
  const settings = snapshot.settings.map((setting): VaultRecord => {
    if (setting.key !== YUBICO_CREDENTIALS) return setting;
    const value = setting.value as Record<string, unknown> | null;
    return { ...setting, value: { ...value, secretKey: apply.yubicoSecret(text(value?.secretKey, 'the Yubico secret key')) } };
  });
  return { ...snapshot, users, twoFactorProviders, settings };
}

// For an archive.
export const openSnapshotSecrets = (snapshot: Snapshot, box: SecretBox): Snapshot =>
  transform(snapshot, {
    recoveryCode: (userId, value) => openRecoveryCode(box, userId, value as Sealed),
    totpSecret: (userId, value) => openTotpSecret(box, userId, value as Sealed),
    yubicoSecret: (value) => openYubicoSecret(box, value as Sealed),
  });

// For a restore.
export const sealSnapshotSecrets = (snapshot: Snapshot, box: SecretBox): Snapshot =>
  transform(snapshot, {
    recoveryCode: (userId, value) => sealRecoveryCode(box, userId, value),
    totpSecret: (userId, value) => sealTotpSecret(box, userId, value),
    yubicoSecret: (value) => sealYubicoSecret(box, value),
  });
