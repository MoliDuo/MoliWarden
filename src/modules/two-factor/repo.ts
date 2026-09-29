import type { Executor } from '../../platform/db';
import type { YubicoCredentials } from './yubico';

// Devices that may skip two-step login ("remember me"), stored under a hash
// of the token and bound to the security stamp they were issued under.

export async function saveRememberToken(
  db: Executor,
  key: string,
  userId: string,
  deviceIdentifier: string,
  securityStamp: string,
  expiresAt: number,
): Promise<void> {
  await db
    .insertInto('trusted_two_factor_device_tokens')
    .values({ token: key, user_id: userId, device_identifier: deviceIdentifier, security_stamp: securityStamp, expires_at: expiresAt })
    .execute();
}

export async function hasRememberToken(
  db: Executor,
  key: string,
  userId: string,
  deviceIdentifier: string,
  securityStamp: string,
  now: number,
): Promise<boolean> {
  const row = await db
    .selectFrom('trusted_two_factor_device_tokens')
    .select('token')
    .where('token', '=', key)
    .where('user_id', '=', userId)
    .where('device_identifier', '=', deviceIdentifier)
    .where('security_stamp', '=', securityStamp)
    .where('expires_at', '>=', now)
    .executeTakeFirst();
  return !!row;
}

// The devices that currently skip two-step login, latest expiry first.
export async function listRememberedDevices(
  db: Executor,
  userId: string,
  now: number,
): Promise<Array<{ identifier: string; expiresAt: number; tokenCount: number }>> {
  const rows = await db
    .selectFrom('trusted_two_factor_device_tokens')
    .select((eb) => ['device_identifier', eb.fn.max('expires_at').as('expires_at'), eb.fn.countAll<string>().as('token_count')])
    .where('user_id', '=', userId)
    .where('expires_at', '>=', now)
    .groupBy('device_identifier')
    .orderBy('expires_at', 'desc')
    .execute();
  return rows.map((row) => ({ identifier: row.device_identifier, expiresAt: Number(row.expires_at), tokenCount: Number(row.token_count) }));
}

// Moves the expiry of a device's unexpired tokens. Returns how many there were.
export async function extendRememberTokens(
  db: Executor,
  userId: string,
  deviceIdentifier: string,
  expiresAt: number,
  now: number,
): Promise<number> {
  const result = await db
    .updateTable('trusted_two_factor_device_tokens')
    .set({ expires_at: expiresAt })
    .where('user_id', '=', userId)
    .where('device_identifier', '=', deviceIdentifier)
    .where('expires_at', '>=', now)
    .executeTakeFirst();
  return Number(result.numUpdatedRows);
}

// Forgets the tokens of the given devices, or of all the user's devices.
export async function deleteRememberTokens(db: Executor, userId: string, deviceIdentifiers?: string[]): Promise<number> {
  if (deviceIdentifiers && !deviceIdentifiers.length) return 0;
  let query = db.deleteFrom('trusted_two_factor_device_tokens').where('user_id', '=', userId);
  if (deviceIdentifiers) query = query.where('device_identifier', 'in', deviceIdentifiers);
  const result = await query.executeTakeFirst();
  return Number(result.numDeletedRows);
}

// Records an authenticator time step as used. False if it was used before.
export async function useTotpStep(db: Executor, userId: string, step: number, now: number): Promise<boolean> {
  const result = await db
    .insertInto('totp_login_replays')
    .values({ user_id: userId, time_counter: step, consumed_at: now })
    .onConflict((oc) => oc.columns(['user_id', 'time_counter']).doNothing())
    .executeTakeFirst();
  return Number(result.numInsertedOrUpdatedRows ?? 0n) > 0;
}

// The server's Yubico API credentials live in the config table.

const CLIENT_ID = 'globalSettings__yubico__clientId';
const SECRET_KEY = 'globalSettings__yubico__key';
export const YUBICO_BOOTSTRAP_CLAIM = 'yubico.bootstrap.claim.v1';

export async function findYubicoCredentials(db: Executor): Promise<YubicoCredentials | null> {
  const rows = await db.selectFrom('config').selectAll().where('key', 'in', [CLIENT_ID, SECRET_KEY]).execute();
  const value = (key: string) => rows.find((row) => row.key === key)?.value.trim() ?? '';
  const clientId = value(CLIENT_ID);
  const secretKey = value(SECRET_KEY);
  return clientId && secretKey ? { clientId, secretKey } : null;
}

export async function saveYubicoCredentials(db: Executor, credentials: YubicoCredentials): Promise<void> {
  await db
    .insertInto('config')
    .values([
      { key: CLIENT_ID, value: credentials.clientId },
      { key: SECRET_KEY, value: credentials.secretKey },
    ])
    .onConflict((oc) => oc.column('key').doUpdateSet((eb) => ({ value: eb.ref('excluded.value') })))
    .execute();
}

// A short-lived claim, so that only one request asks Yubico for new
// credentials at a time. Returns the claim, or null if another holds it.
export async function claimYubicoBootstrap(db: Executor, now: number, ttlMs: number): Promise<string | null> {
  const current = await db.selectFrom('config').select('value').where('key', '=', YUBICO_BOOTSTRAP_CLAIM).executeTakeFirst();
  if (current && Number(current.value.split(':')[0]) < now) {
    await db.deleteFrom('config').where('key', '=', YUBICO_BOOTSTRAP_CLAIM).where('value', '=', current.value).execute();
  }
  const claim = `${now + ttlMs}:${crypto.randomUUID()}`;
  const result = await db
    .insertInto('config')
    .values({ key: YUBICO_BOOTSTRAP_CLAIM, value: claim })
    .onConflict((oc) => oc.column('key').doNothing())
    .executeTakeFirst();
  return Number(result.numInsertedOrUpdatedRows ?? 0n) > 0 ? claim : null;
}

export async function releaseYubicoBootstrap(db: Executor, claim: string): Promise<void> {
  await db.deleteFrom('config').where('key', '=', YUBICO_BOOTSTRAP_CLAIM).where('value', '=', claim).execute();
}
