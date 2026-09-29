import { sql } from 'kysely';
import type { Executor } from '../../platform/db';
import type { RowUpdate } from '../../platform/db/schema';
import type { User } from '../../types';
import { toUser } from './rows';

export async function countUsers(db: Executor): Promise<number> {
  const row = await db.selectFrom('users').select((eb) => eb.fn.countAll<number>().as('count')).executeTakeFirstOrThrow();
  return Number(row.count);
}

export async function findUserById(db: Executor, id: string): Promise<User | null> {
  const row = await db.selectFrom('users').selectAll().where('id', '=', id).executeTakeFirst();
  return row ? toUser(row) : null;
}

export async function findUserByEmail(db: Executor, email: string): Promise<User | null> {
  const row = await db.selectFrom('users').selectAll().where('email', '=', email.trim().toLowerCase()).executeTakeFirst();
  return row ? toUser(row) : null;
}

export async function insertUser(db: Executor, user: User): Promise<void> {
  await db
    .insertInto('users')
    .values({
      id: user.id,
      email: user.email.toLowerCase(),
      name: user.name,
      master_password_hint: user.masterPasswordHint,
      master_password_hash: user.masterPasswordHash,
      key: user.key,
      private_key: user.privateKey,
      public_key: user.publicKey,
      kdf_type: user.kdfType,
      kdf_iterations: user.kdfIterations,
      kdf_memory: user.kdfMemory ?? null,
      kdf_parallelism: user.kdfParallelism ?? null,
      security_stamp: user.securityStamp,
      role: user.role,
      status: user.status,
      verify_devices: 0,
      totp_secret: null,
      totp_recovery_code: null,
      yubikey_key1: null,
      yubikey_key2: null,
      yubikey_key3: null,
      yubikey_key4: null,
      yubikey_key5: null,
      yubikey_nfc: 0,
      api_key: user.apiKey,
      key_id: null,
      created_at: user.createdAt,
      updated_at: user.updatedAt,
    })
    .execute();
}

// Registrations run one at a time, so "the first account becomes admin"
// and "this email is free" hold until the transaction commits.
export async function lockRegistrations(tx: Executor): Promise<void> {
  await sql`SELECT pg_advisory_xact_lock(hashtext('moliwarden.registration'))`.execute(tx);
}

// The account fields services change directly.
export type UserChanges = Partial<
  Pick<
    User,
    | 'name'
    | 'masterPasswordHint'
    | 'masterPasswordHash'
    | 'key'
    | 'privateKey'
    | 'publicKey'
    | 'securityStamp'
    | 'apiKey'
    | 'keyId'
    | 'totpSecret'
    | 'totpRecoveryCode'
    | 'yubikeyNfc'
  > & {
    yubikeys: (string | null)[];
  }
>;

const COLUMNS = {
  name: 'name',
  masterPasswordHint: 'master_password_hint',
  masterPasswordHash: 'master_password_hash',
  key: 'key',
  privateKey: 'private_key',
  publicKey: 'public_key',
  securityStamp: 'security_stamp',
  apiKey: 'api_key',
  keyId: 'key_id',
  totpSecret: 'totp_secret',
  totpRecoveryCode: 'totp_recovery_code',
} as const satisfies Record<string, keyof RowUpdate<'users'>>;

// Returns the new updated-at time.
export async function updateUser(db: Executor, id: string, changes: UserChanges): Promise<string> {
  const updatedAt = new Date().toISOString();
  const set: Record<string, unknown> = { updated_at: updatedAt };
  for (const [field, column] of Object.entries(COLUMNS)) {
    const value = changes[field as keyof typeof COLUMNS];
    if (value !== undefined) set[column] = value;
  }
  if (changes.yubikeyNfc !== undefined) set.yubikey_nfc = changes.yubikeyNfc ? 1 : 0;
  if (changes.yubikeys !== undefined) {
    const [key1 = null, key2 = null, key3 = null, key4 = null, key5 = null] = changes.yubikeys;
    Object.assign(set, { yubikey_key1: key1, yubikey_key2: key2, yubikey_key3: key3, yubikey_key4: key4, yubikey_key5: key5 });
  }
  await db.updateTable('users').set(set as RowUpdate<'users'>).where('id', '=', id).execute();
  return updatedAt;
}

// Records the id clients report for the user key, once; false when one is
// already recorded.
export async function claimUserKeyId(db: Executor, id: string, keyId: string): Promise<boolean> {
  const result = await db
    .updateTable('users')
    .set({ key_id: keyId })
    .where('id', '=', id)
    .where('key_id', 'is', null)
    .executeTakeFirst();
  return Number(result.numUpdatedRows) > 0;
}

export async function isInviteActive(db: Executor, code: string): Promise<boolean> {
  const row = await db
    .selectFrom('invites')
    .select('code')
    .where('code', '=', code)
    .where('status', '=', 'active')
    .where('expires_at', '>', new Date().toISOString())
    .executeTakeFirst();
  return !!row;
}

// Spends an active invite on the new account; false when there is none.
export async function useInvite(db: Executor, code: string, userId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .updateTable('invites')
    .set({ status: 'used', used_by: userId, updated_at: now })
    .where('code', '=', code)
    .where('status', '=', 'active')
    .where('expires_at', '>', now)
    .executeTakeFirst();
  return Number(result.numUpdatedRows) > 0;
}

// When anything in the user's vault last changed. Clients compare it with
// their copy to decide whether to sync.
export async function findRevisionDate(db: Executor, userId: string): Promise<string> {
  const row = await db.selectFrom('user_revisions').select('revision_date').where('user_id', '=', userId).executeTakeFirst();
  if (row) return row.revision_date;
  const now = new Date().toISOString();
  await db
    .insertInto('user_revisions')
    .values({ user_id: userId, revision_date: now })
    .onConflict((oc) => oc.column('user_id').doNothing())
    .execute();
  return now;
}

export async function touchRevisionDate(db: Executor, userId: string, date: string): Promise<void> {
  await db
    .insertInto('user_revisions')
    .values({ user_id: userId, revision_date: date })
    .onConflict((oc) => oc.column('user_id').doUpdateSet({ revision_date: date }))
    .execute();
}
