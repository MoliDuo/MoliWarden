import { z } from 'zod';
import { text } from '../../http/body';

const flag = z.preprocess((value) => value === true || value === 'true' || value === 1 || value === '1', z.boolean());

// Settings changes are confirmed with the master password hash; some
// clients name the field differently.
const secretFields = {
  masterPasswordHash: text,
  otp: text,
  secret: text,
  password: text,
};

export const secretBody = z.object(secretFields);
export type SecretBody = z.output<typeof secretBody>;
export const secretOf = (body: Partial<SecretBody>): string | null =>
  body.masterPasswordHash || body.otp || body.secret || body.password || null;

export const authenticatorBody = z.object({ key: text, token: text, userVerificationToken: text });

export const disableBody = secretBody.extend({
  type: z.preprocess((value) => (value == null || value === '' ? 0 : Number(value)), z.number()),
});

export const yubiKeyBody = secretBody.extend({
  key1: text,
  key2: text,
  key3: text,
  key4: text,
  key5: text,
  nfc: flag,
});

export const yubicoConfigBody = secretBody.extend({
  yubicoClientId: text,
  clientId: text,
  yubicoSecretKey: text,
  secretKey: text,
});

// The OTP is the YubiKey's, so only the password fields confirm the user.
export const yubicoBootstrapBody = z.object({ masterPasswordHash: text, secret: text, otp: text, token: text });

export const securityKeyBody = secretBody.extend({ deviceResponse: z.unknown().optional(), name: text });

export const securityKeyDeleteBody = secretBody.extend({
  id: z.preprocess((value) => Number(value), z.number()),
});

export const deviceVerificationBody = z.object({ enabled: z.unknown().optional(), verifyDevices: z.unknown().optional() });

export const totpBody = z.object({
  enabled: z.boolean().optional(),
  secret: text,
  token: text,
  masterPasswordHash: text,
  userVerificationToken: text,
});

export const recoveryCodeBody = z.object({ masterPasswordHash: text, master_password_hash: text, password: text });

export const recoverBody = z.object({
  email: text,
  username: text,
  masterPasswordHash: text,
  password: text,
  recoveryCode: text,
  twoFactorToken: text,
  recovery_code: text,
});
