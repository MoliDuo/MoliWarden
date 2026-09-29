import type { Executor } from './index';

// Server-wide values that are not configuration: things the server set up
// for itself or that an admin changed at runtime. Each is one JSON value.

export async function readSetting<T>(db: Executor, key: string): Promise<T | null> {
  const row = await db.selectFrom('settings').select('value').where('key', '=', key).executeTakeFirst();
  return row ? (row.value as T) : null;
}

export async function writeSetting(db: Executor, key: string, value: unknown): Promise<void> {
  const json = JSON.stringify(value);
  await db
    .insertInto('settings')
    .values({ key, value: json })
    .onConflict((oc) => oc.column('key').doUpdateSet({ value: json }))
    .execute();
}

// Writes the value unless the key has one; returns the value the key ends up with.
export async function writeSettingOnce<T>(db: Executor, key: string, value: T): Promise<T> {
  await db
    .insertInto('settings')
    .values({ key, value: JSON.stringify(value) })
    .onConflict((oc) => oc.column('key').doNothing())
    .execute();
  return (await readSetting<T>(db, key)) ?? value;
}

export async function deleteSetting(db: Executor, key: string): Promise<void> {
  await db.deleteFrom('settings').where('key', '=', key).execute();
}
