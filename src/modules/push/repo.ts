import type { Executor } from '../../platform/db';

// The server's installation at the push relay, kept in the config table.

const INSTALLATION_ID = 'push.installation.id';
const INSTALLATION_KEY = 'push.installation.key';

export interface Installation {
  id: string;
  key: string;
}

export async function findInstallation(db: Executor): Promise<Installation | null> {
  const rows = await db.selectFrom('config').selectAll().where('key', 'in', [INSTALLATION_ID, INSTALLATION_KEY]).execute();
  const value = (key: string) => rows.find((row) => row.key === key)?.value.trim() ?? '';
  const id = value(INSTALLATION_ID);
  const key = value(INSTALLATION_KEY);
  return id && key ? { id, key } : null;
}

export async function saveInstallation(db: Executor, installation: Installation): Promise<void> {
  await db
    .insertInto('config')
    .values([
      { key: INSTALLATION_ID, value: installation.id },
      { key: INSTALLATION_KEY, value: installation.key },
    ])
    .onConflict((oc) => oc.column('key').doUpdateSet((eb) => ({ value: eb.ref('excluded.value') })))
    .execute();
}

// The user's devices, and whether any of them can receive pushes.
export async function findPushDevices(
  db: Executor,
  userId: string,
): Promise<Array<{ identifier: string; pushUuid: string | null; registered: boolean }>> {
  const rows = await db
    .selectFrom('devices')
    .select(['device_identifier', 'push_uuid', 'push_token'])
    .where('user_id', '=', userId)
    .execute();
  return rows.map((row) => ({ identifier: row.device_identifier, pushUuid: row.push_uuid, registered: !!row.push_token }));
}
