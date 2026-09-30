import { unzipSync } from 'fflate';
import { buildArchive, type Archive } from '../../src/modules/backup/archive';
import { convertBackupTables, type LegacyTables, type Report } from './transform';

// A backup archive of the old backend (format 1: manifest.json, db.json
// with the rows of its tables, attachments/<cipher>/<id>.bin) as one of
// today's (format 2).

export class BackupFormatError extends Error {}

function readJson(entries: Record<string, Uint8Array>, name: string): unknown {
  const bytes = entries[name];
  if (!bytes) throw new BackupFormatError(`${name} is missing: this is not a backup of the earlier version.`);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new BackupFormatError(`${name} is not valid JSON.`);
  }
}

export async function convertBackupArchive(bytes: Uint8Array): Promise<{ archive: Archive; report: Report }> {
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(bytes);
  } catch {
    throw new BackupFormatError('The file is not a zip archive.');
  }
  const manifest = readJson(entries, 'manifest.json') as { formatVersion?: unknown; exportedAt?: unknown; includes?: { attachments?: unknown } };
  if (manifest?.formatVersion !== 1) throw new BackupFormatError(`Expected format version 1, found ${String(manifest?.formatVersion)}.`);
  const tables = readJson(entries, 'db.json') as LegacyTables;
  if (!tables || typeof tables !== 'object') throw new BackupFormatError('db.json is malformed.');

  const { snapshot, report } = await convertBackupTables(tables);
  const files = new Map<string, Uint8Array>();
  for (const [name, file] of Object.entries(entries)) {
    const match = /^attachments\/([^/]+)\/([^/]+)\.bin$/.exec(name);
    if (match) files.set(`${match[1]}/${match[2]}`, file);
  }
  const exportedAt = typeof manifest.exportedAt === 'string' ? new Date(manifest.exportedAt) : new Date();
  const archive = buildArchive(snapshot, {
    date: Number.isNaN(exportedAt.getTime()) ? new Date() : exportedAt,
    timeZone: 'UTC',
    includeAttachments: manifest.includes?.attachments === true,
    files,
  });
  return { archive, report };
}
