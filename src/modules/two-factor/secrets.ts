import type { Sealed, SecretBox } from '../../platform/crypto';

// The secrets of two-step login, sealed with ENCRYPTION_KEY where they are
// stored. Each context names the value and its owner.

export const sealTotpSecret = (box: SecretBox, userId: string, secret: string) => box.seal(secret, `totp:${userId}`);
export const openTotpSecret = (box: SecretBox, userId: string, sealed: Sealed) => box.open(sealed, `totp:${userId}`);

export const sealRecoveryCode = (box: SecretBox, userId: string, code: string) => box.seal(code, `recovery-code:${userId}`);
export const openRecoveryCode = (box: SecretBox, userId: string, sealed: Sealed) => box.open(sealed, `recovery-code:${userId}`);

export const sealYubicoSecret = (box: SecretBox, secretKey: string) => box.seal(secretKey, 'yubico.credentials');
export const openYubicoSecret = (box: SecretBox, sealed: Sealed) => box.open(sealed, 'yubico.credentials');
