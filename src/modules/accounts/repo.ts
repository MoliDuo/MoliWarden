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

// The account fields services change directly.
export type UserChanges = Partial<
  Pick<User, 'securityStamp' | 'totpSecret' | 'totpRecoveryCode' | 'yubikeyNfc'> & {
    yubikeys: (string | null)[];
  }
>;

export async function updateUser(db: Executor, id: string, changes: UserChanges): Promise<void> {
  const set: RowUpdate<'users'> = { updated_at: new Date().toISOString() };
  if (changes.securityStamp !== undefined) set.security_stamp = changes.securityStamp;
  if (changes.totpSecret !== undefined) set.totp_secret = changes.totpSecret;
  if (changes.totpRecoveryCode !== undefined) set.totp_recovery_code = changes.totpRecoveryCode;
  if (changes.yubikeyNfc !== undefined) set.yubikey_nfc = changes.yubikeyNfc ? 1 : 0;
  if (changes.yubikeys !== undefined) {
    const [key1 = null, key2 = null, key3 = null, key4 = null, key5 = null] = changes.yubikeys;
    Object.assign(set, { yubikey_key1: key1, yubikey_key2: key2, yubikey_key3: key3, yubikey_key4: key4, yubikey_key5: key5 });
  }
  await db.updateTable('users').set(set).where('id', '=', id).execute();
}
