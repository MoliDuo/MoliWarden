import { z } from 'zod';
import { text } from '../../http/body';

// The token endpoint's form. OAuth fields are snake_case; the Bitwarden
// extensions arrive in either casing and are normalized to camelCase.
export const tokenForm = z.object({
  grant_type: text,
  scope: text,
  client_id: text,
  client_secret: text,

  // password
  username: text,
  password: text,
  authRequest: text,
  twoFactorProvider: text,
  twoFactorToken: text,
  twoFactorRemember: text,

  // webauthn
  token: text,
  deviceResponse: z.unknown().optional(),

  // refresh_token
  refresh_token: text,

  // send_access
  send_id: text,
  sendId: text,
  password_hash_b64: text,
  passwordHashB64: text,
  passwordHash: text,
  password_hash: text,

  // The signing-in device.
  deviceIdentifier: text,
  device_identifier: text,
  deviceName: text,
  device_name: text,
  deviceType: text,
  device_type: text,
  devicePushToken: text,
  device_push_token: text,
});

export type TokenForm = z.output<typeof tokenForm>;

export const revocationForm = z.object({ token: text });

export const preloginBody = z.object({ email: text });
