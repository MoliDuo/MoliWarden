import type { Executor } from '../../platform/db';
import { readSetting, writeSetting } from '../../platform/db/settings';

// The server's installation at the push relay.
const INSTALLATION = 'push.installation';

export interface Installation {
  id: string;
  key: string;
}

export async function findInstallation(db: Executor): Promise<Installation | null> {
  const installation = await readSetting<Installation>(db, INSTALLATION);
  return installation?.id && installation.key ? installation : null;
}

export async function saveInstallation(db: Executor, installation: Installation): Promise<void> {
  await writeSetting(db, INSTALLATION, { id: installation.id, key: installation.key });
}

// The user's devices, and whether any of them can receive pushes.
export async function findPushDevices(
  db: Executor,
  userId: string,
): Promise<Array<{ identifier: string; pushUuid: string; registered: boolean }>> {
  const rows = await db
    .selectFrom('devices')
    .select(['identifier', 'push_uuid', 'push_token'])
    .where('user_id', '=', userId)
    .execute();
  return rows.map((row) => ({ identifier: row.identifier, pushUuid: row.push_uuid, registered: !!row.push_token }));
}
