import type { Deps } from '../../main/deps';
import { conflict } from '../../http/errors';
import { listUsers } from '../admin/repo';
import { buildArchive, type Archive } from './archive';
import { readRuntimes, readSnapshot, readStoredSettings, SETTINGS_KEY, writeStoredSettings } from './repo';
import { openSettings, portableOnly, sealSettings } from './settings-crypto';
import { defaultSettings, parseStoredSettings, storedSettings, withRuntime, type Destination, type Settings } from './settings';

// The backup settings as stored, and the archive of the whole instance.

// The settings with each destination's history. Settings restored from
// another server cannot be read until an admin repairs them.
export async function loadSettings(deps: Deps): Promise<Settings> {
  const raw = await readStoredSettings(deps.db);
  const runtimes = await readRuntimes(deps.db);
  if (!raw) return withRuntime(defaultSettings(), runtimes);
  const json = openSettings(raw, deps.config.jwtSecret);
  if (json === null) throw conflict('Backup settings need administrator reactivation after restore');
  return withRuntime(parseStoredSettings(json), runtimes);
}

// Seals the settings for this server and for every active admin.
export async function saveSettings(deps: Deps, settings: Settings): Promise<void> {
  const sealed = sealSettings(storedSettings(settings), deps.config.jwtSecret, await listUsers(deps.db));
  await writeStoredSettings(deps.db, sealed);
}

export const destinationSummary = (destination: Destination) => ({
  destinationId: destination.id,
  destinationName: destination.name,
  destinationType: destination.type,
});

// An archive of the instance as it is now. The backup settings go in only
// in their portable form: the destinations' credentials stay readable for
// the admins alone.
export async function createArchive(deps: Deps, date: Date, timeZone: string, includeAttachments: boolean): Promise<Archive> {
  const snapshot = await deps.db
    .transaction()
    .setIsolationLevel('repeatable read')
    .execute((tx) => readSnapshot(tx));
  snapshot.settings = snapshot.settings.flatMap((record) => {
    if (record.key !== SETTINGS_KEY) return [record];
    const value = portableOnly(String(record.value));
    return value ? [{ key: record.key, value }] : [];
  });
  return buildArchive(snapshot, { date, timeZone, includeAttachments });
}
