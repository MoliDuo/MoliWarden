import { randomUUID } from 'node:crypto';
import {
  BACKUP_DEFAULT_INTERVAL_HOURS,
  BACKUP_DEFAULT_RETENTION_COUNT,
  BACKUP_DEFAULT_START_TIME,
  createDefaultBackupRuntimeState,
  createDefaultBackupDestinationName,
  type BackupDestinationRecord,
  type BackupRuntimeState,
  type BackupScheduleConfig,
  type BackupSettings,
  type S3BackupDestination,
  type WebDavBackupDestination,
} from '../../../shared/backup-schema';
import { badRequest, notFound } from '../../http/errors';
import { checkEndpointUrl } from './endpoint';

// Where backups go and when. The shapes are shared with the web vault
// (shared/backup-schema.ts); this file checks what admins send.

export type Destination = BackupDestinationRecord;
export type Settings = BackupSettings;
export type Runtime = BackupRuntimeState;

export const REDACTED = '********';
const MAX_DESTINATIONS = 24;

// Until an admin adds one, there is no destination.
export const defaultSettings = (): Settings => ({ destinations: [] });
export const emptyRuntime = (): Runtime => createDefaultBackupRuntimeState();

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const trimmed = (value: unknown) => (typeof value === 'string' || typeof value === 'number' ? String(value).trim() : '');
const path = (value: unknown) => trimmed(value).replace(/\\/g, '/').split('/').filter(Boolean).join('/');

function timezone(value: string): string {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value });
    return value;
  } catch {
    throw badRequest('Invalid backup timezone');
  }
}

function intervalHours(value: unknown): number {
  const hours = value == null || value === '' ? BACKUP_DEFAULT_INTERVAL_HOURS : Number(value);
  if (!Number.isInteger(hours) || hours < 1 || hours > 99) throw badRequest('Backup interval hours must be between 1 and 99');
  return hours;
}

function startTime(value: unknown): string {
  const match = /^(\d{1,2})(?::(\d{1,2}))?$/.exec(trimmed(value) || BACKUP_DEFAULT_START_TIME);
  const hour = Number(match?.[1]);
  const minute = Number(match?.[2] ?? 0);
  if (!match || hour > 23 || minute > 59) throw badRequest('Backup start time must be in HH:mm format');
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function retentionCount(value: unknown): number | null {
  if (value === null || trimmed(value) === '') return null;
  const count = Number(value);
  if (!Number.isInteger(count) || count < 1 || count > 1000) throw badRequest('Backup retention count must be between 1 and 1000');
  return count;
}

function schedule(input: Record<string, unknown>, previous: BackupScheduleConfig | undefined): BackupScheduleConfig {
  const pick = (key: keyof BackupScheduleConfig) => (key in input ? input[key] : previous?.[key]);
  return {
    enabled: pick('enabled') === true,
    intervalHours: intervalHours(pick('intervalHours')),
    startTime: startTime(pick('startTime')),
    timezone: timezone(trimmed(pick('timezone')) || 'UTC'),
    retentionCount: retentionCount('retentionCount' in input || previous ? pick('retentionCount') : BACKUP_DEFAULT_RETENTION_COUNT),
  };
}

// A secret the admin left as shown (redacted) or did not send is kept; an
// empty one is cleared.
function secret(value: unknown, previous: string | undefined): string {
  if (value === undefined || value === null || value === REDACTED) return previous ?? '';
  return String(value);
}

// The connection details; required only once the schedule needs them.
function connection(type: Destination['type'], input: Record<string, unknown>, previous: Destination | undefined, allowPrivate: boolean) {
  const endpoint = (value: string, label: string) => (value ? checkEndpointUrl(value, label, allowPrivate) : '');
  if (type === 's3') {
    const before = previous?.type === 's3' ? (previous.destination as S3BackupDestination) : undefined;
    return {
      endpoint: endpoint(trimmed(input.endpoint), 'S3 endpoint'),
      bucket: trimmed(input.bucket),
      addressingStyle: input.addressingStyle === 'virtual-hosted-style' ? 'virtual-hosted-style' : 'path-style',
      region: trimmed(input.region) || 'auto',
      accessKeyId: trimmed(input.accessKeyId),
      secretAccessKey: secret(input.secretAccessKey, before?.secretAccessKey).trim(),
      rootPath: path(input.rootPath),
    } satisfies S3BackupDestination;
  }
  const before = previous?.type === 'webdav' ? (previous.destination as WebDavBackupDestination) : undefined;
  return {
    baseUrl: endpoint(trimmed(input.baseUrl), 'WebDAV server URL'),
    username: trimmed(input.username),
    password: secret(input.password, before?.password),
    remotePath: path(input.remotePath),
  } satisfies WebDavBackupDestination;
}

// Why the destination cannot be used yet, or null.
export function missingSetting(destination: Destination): string | null {
  if (destination.type === 's3') {
    const s3 = destination.destination as S3BackupDestination;
    if (!s3.endpoint) return 'S3 endpoint is required';
    if (!s3.bucket) return 'S3 bucket is required';
    if (!s3.accessKeyId) return 'S3 access key is required';
    if (!s3.secretAccessKey) return 'S3 secret key is required';
    return null;
  }
  const dav = destination.destination as WebDavBackupDestination;
  if (!dav.baseUrl) return 'WebDAV server URL is required';
  if (!dav.username) return 'WebDAV username is required';
  if (!dav.password) return 'WebDAV password is required';
  return null;
}

function destination(input: unknown, index: number, previousById: Map<string, Destination>, allowPrivate: boolean): Destination {
  if (!isObject(input)) throw badRequest('Backup destination is invalid');
  const type = input.type;
  if (type !== 's3' && type !== 'webdav') throw badRequest('Backup destination type is invalid');
  const id = trimmed(input.id) || randomUUID();
  const previous = previousById.get(id);
  const result: Destination = {
    id,
    name: trimmed(input.name) || previous?.name || createDefaultBackupDestinationName(type, index + 1),
    type,
    includeAttachments: typeof input.includeAttachments === 'boolean' ? input.includeAttachments : (previous?.includeAttachments ?? false),
    destination: connection(type, isObject(input.destination) ? input.destination : {}, previous, allowPrivate),
    schedule: schedule(isObject(input.schedule) ? input.schedule : {}, previous?.schedule),
    runtime: previous?.runtime ?? emptyRuntime(),
  };
  const missing = result.schedule.enabled ? missingSetting(result) : null;
  if (missing) throw badRequest(missing);
  return result;
}

// The settings an admin sends, on top of the current ones: secrets that are
// not sent and the destinations' run history carry over.
export function settingsFrom(input: { destinations?: unknown[] }, previous: Settings, allowPrivate: boolean): Settings {
  const list = input.destinations ?? previous.destinations;
  if (list.length > MAX_DESTINATIONS) throw badRequest(`You can save up to ${MAX_DESTINATIONS} backup destinations`);
  const previousById = new Map(previous.destinations.map((entry) => [entry.id, entry]));
  const destinations = list.map((entry, index) => destination(entry, index, previousById, allowPrivate));
  if (new Set(destinations.map((entry) => entry.id)).size !== destinations.length) {
    throw badRequest('Backup destination ids must be unique');
  }
  return { destinations };
}

// Settings as stored, read back leniently: a destination the current rules
// would refuse is still shown, so the admin can fix it.
export function parseStoredSettings(json: string): Settings {
  const value = JSON.parse(json) as { destinations?: unknown };
  const entries = Array.isArray(value.destinations) ? value.destinations : [];
  const parsed: Destination[] = [];
  for (const [index, entry] of entries.entries()) {
    const paused = isObject(entry) ? { ...entry, schedule: { ...(isObject(entry.schedule) ? entry.schedule : {}), enabled: false } } : entry;
    for (const candidate of [entry, paused]) {
      try {
        parsed.push(destination(candidate, index, new Map(), true));
        break;
      } catch {
        // Try again with the schedule paused, or leave the entry out.
      }
    }
  }
  return { destinations: parsed };
}

// What is stored: the history is kept separately.
export const storedSettings = (settings: Settings) =>
  JSON.stringify({ destinations: settings.destinations.map(({ runtime: _runtime, ...entry }) => entry) });

export function withRuntime(settings: Settings, runtimes: Record<string, Runtime>): Settings {
  return { destinations: settings.destinations.map((entry) => ({ ...entry, runtime: runtimes[entry.id] ?? emptyRuntime() })) };
}

export function redacted(settings: Settings): Settings {
  const hide = (value: string) => (value ? REDACTED : '');
  return {
    destinations: settings.destinations.map((entry) => {
      if (entry.type === 's3') {
        const s3 = entry.destination as S3BackupDestination;
        return { ...entry, destination: { ...s3, secretAccessKey: hide(s3.secretAccessKey) } };
      }
      const dav = entry.destination as WebDavBackupDestination;
      return { ...entry, destination: { ...dav, password: hide(dav.password) } };
    }),
  };
}

export function findDestination(settings: Settings, id: string | null | undefined): Destination {
  const found = id ? settings.destinations.find((entry) => entry.id === id) : settings.destinations[0];
  if (!found) throw notFound('Backup destination not found');
  return found;
}
