import type { Executor } from '../../platform/db';
import { readSetting, writeSetting } from '../../platform/db/settings';
import type { YubicoCredentials } from './yubico';

// --- Providers ---------------------------------------------------------------

// The authenticator app and YubiKeys a user set up. Security keys are
// WebAuthn credentials and live with the passkeys.

export const TOTP = 0;
export const YUBIKEY = 3;

export interface TotpData {
  secret: string;
}

export interface YubiKeyData {
  // The public ids in the five slots clients show, empty ones null.
  keys: (string | null)[];
  nfc: boolean;
}

export async function findProviders(db: Executor, userId: string): Promise<{ totp: TotpData | null; yubiKey: YubiKeyData | null }> {
  const rows = await db.selectFrom('two_factor_providers').select(['type', 'data']).where('user_id', '=', userId).execute();
  const data = (type: number) => rows.find((row) => row.type === type)?.data ?? null;
  return { totp: data(TOTP) as TotpData | null, yubiKey: data(YUBIKEY) as YubiKeyData | null };
}

export async function saveProvider(db: Executor, userId: string, type: typeof TOTP, data: TotpData): Promise<void>;
export async function saveProvider(db: Executor, userId: string, type: typeof YUBIKEY, data: YubiKeyData): Promise<void>;
export async function saveProvider(db: Executor, userId: string, type: number, data: TotpData | YubiKeyData): Promise<void> {
  const json = JSON.stringify(data);
  await db
    .insertInto('two_factor_providers')
    .values({ user_id: userId, type, data: json })
    .onConflict((oc) => oc.columns(['user_id', 'type']).doUpdateSet({ data: json }))
    .execute();
}

// One provider, or all of them.
export async function deleteProviders(db: Executor, userId: string, type?: number): Promise<void> {
  let query = db.deleteFrom('two_factor_providers').where('user_id', '=', userId);
  if (type !== undefined) query = query.where('type', '=', type);
  await query.execute();
}

// Which of the users have a provider or a security key, in one query.
export async function usersWithSecondFactor(db: Executor, userIds: string[]): Promise<Set<string>> {
  if (!userIds.length) return new Set();
  const rows = await db
    .selectFrom('two_factor_providers')
    .select('user_id')
    .where('user_id', 'in', userIds)
    .union((eb) =>
      eb
        .selectFrom('webauthn_credentials')
        .select('user_id')
        .where('user_id', 'in', userIds)
        .where('purpose', '=', 'twoFactor'),
    )
    .execute();
  return new Set(rows.map((row) => row.user_id));
}

// --- Remembered devices ------------------------------------------------------

// Devices that may skip two-step login ("remember me"), stored under a hash
// of the token and bound to the security stamp they were issued under.

export async function saveRememberToken(
  db: Executor,
  tokenHash: Buffer,
  userId: string,
  deviceIdentifier: string,
  securityStamp: string,
  expiresAt: Date,
): Promise<void> {
  await db
    .insertInto('two_factor_remember_tokens')
    .values({
      token_hash: tokenHash,
      user_id: userId,
      device_identifier: deviceIdentifier,
      security_stamp: securityStamp,
      expires_at: expiresAt.toISOString(),
    })
    .execute();
}

export async function hasRememberToken(
  db: Executor,
  tokenHash: Buffer,
  userId: string,
  deviceIdentifier: string,
  securityStamp: string,
): Promise<boolean> {
  const row = await db
    .selectFrom('two_factor_remember_tokens')
    .select('user_id')
    .where('token_hash', '=', tokenHash)
    .where('user_id', '=', userId)
    .where('device_identifier', '=', deviceIdentifier)
    .where('security_stamp', '=', securityStamp)
    .where('expires_at', '>=', new Date().toISOString())
    .executeTakeFirst();
  return !!row;
}

// The devices that currently skip two-step login, latest expiry first.
export async function listRememberedDevices(
  db: Executor,
  userId: string,
): Promise<Array<{ identifier: string; expiresAt: string; tokenCount: number }>> {
  const rows = await db
    .selectFrom('two_factor_remember_tokens')
    .select((eb) => ['device_identifier', eb.fn.max('expires_at').as('expires_at'), eb.fn.countAll<string>().as('token_count')])
    .where('user_id', '=', userId)
    .where('expires_at', '>=', new Date().toISOString())
    .groupBy('device_identifier')
    .orderBy('expires_at', 'desc')
    .execute();
  return rows.map((row) => ({ identifier: row.device_identifier, expiresAt: row.expires_at, tokenCount: Number(row.token_count) }));
}

// Moves the expiry of a device's unexpired tokens. Returns how many there were.
export async function extendRememberTokens(db: Executor, userId: string, deviceIdentifier: string, expiresAt: Date): Promise<number> {
  const result = await db
    .updateTable('two_factor_remember_tokens')
    .set({ expires_at: expiresAt.toISOString() })
    .where('user_id', '=', userId)
    .where('device_identifier', '=', deviceIdentifier)
    .where('expires_at', '>=', new Date().toISOString())
    .executeTakeFirst();
  return Number(result.numUpdatedRows);
}

// Forgets the tokens of the given devices, or of all the user's devices.
export async function deleteRememberTokens(db: Executor, userId: string, deviceIdentifiers?: string[]): Promise<number> {
  if (deviceIdentifiers && !deviceIdentifiers.length) return 0;
  let query = db.deleteFrom('two_factor_remember_tokens').where('user_id', '=', userId);
  if (deviceIdentifiers) query = query.where('device_identifier', 'in', deviceIdentifiers);
  const result = await query.executeTakeFirst();
  return Number(result.numDeletedRows);
}

// --- Yubico ------------------------------------------------------------------

// The server's credentials for Yubico's OTP validation API.
const YUBICO_CREDENTIALS = 'yubico.credentials';

export async function findYubicoCredentials(db: Executor): Promise<YubicoCredentials | null> {
  const credentials = await readSetting<YubicoCredentials>(db, YUBICO_CREDENTIALS);
  return credentials?.clientId && credentials.secretKey ? credentials : null;
}

export async function saveYubicoCredentials(db: Executor, credentials: YubicoCredentials): Promise<void> {
  await writeSetting(db, YUBICO_CREDENTIALS, { clientId: credentials.clientId, secretKey: credentials.secretKey });
}
