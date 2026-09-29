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
      api_key: user.apiKey,
      recovery_code: user.recoveryCode,
      key_id: null,
      revision_date: user.createdAt,
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
    | 'recoveryCode'
  >
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
  recoveryCode: 'recovery_code',
} as const satisfies Record<keyof UserChanges, keyof RowUpdate<'users'>>;

// Returns the new updated-at time.
export async function updateUser(db: Executor, id: string, changes: UserChanges): Promise<string> {
  const updatedAt = new Date().toISOString();
  const set: RowUpdate<'users'> = { updated_at: updatedAt };
  for (const [field, column] of Object.entries(COLUMNS)) {
    const value = changes[field as keyof UserChanges];
    if (value !== undefined) Object.assign(set, { [column]: value });
  }
  await db.updateTable('users').set(set).where('id', '=', id).execute();
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
export async function findRevisionDate(db: Executor, userId: string): Promise<string | null> {
  const row = await db.selectFrom('users').select('revision_date').where('id', '=', userId).executeTakeFirst();
  return row?.revision_date ?? null;
}

// Moves the revision date of the users given; returns those that exist.
export async function touchRevisionDates(db: Executor, userIds: string[], date: string): Promise<string[]> {
  if (!userIds.length) return [];
  const rows = await db
    .updateTable('users')
    .set({ revision_date: date })
    .where((eb) => eb('id', '=', eb.fn.any(eb.val(userIds))))
    .returning('id')
    .execute();
  return rows.map((row) => row.id);
}

export async function touchRevisionDate(db: Executor, userId: string, date: string): Promise<void> {
  await touchRevisionDates(db, [userId], date);
}
