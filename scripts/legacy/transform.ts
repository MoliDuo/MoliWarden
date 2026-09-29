import { createDecipheriv, hkdfSync, randomUUID } from 'node:crypto';
import { LIMITS } from '../../src/config/limits';
import { sha256 } from '../../src/platform/crypto';
import type { NewRow } from '../../src/platform/db/schema';
import { normalizeKeys } from '../../src/platform/camel-case';
import { hashMasterPassword } from '../../src/modules/auth/password';
import { KIND_NAMES, type Snapshot, type VaultRecord } from '../../src/modules/backup/archive';
import { parseStoredSettings, storedSettings } from '../../src/modules/backup/settings';
import { readCipherData, writeCipherData } from '../../src/modules/ciphers/model';
import { normalizeCustomEquivalentDomains, normalizeEquivalentDomains, normalizeExcludedGlobalTypes } from '../../src/modules/domains/rules';
import { hashSendPassword } from '../../src/modules/sends/model';
import { normalizeTotpSecret } from '../../src/modules/two-factor/totp';

// Converts the tables of the backend before the rewrite (v1, the NodeWarden
// port) into what MoliWarden stores. The callers read the rows, from the
// old database or from a v1 backup archive, and write the result; nothing
// here touches a database.
//
// Accounts and vaults become a Snapshot, the records of a v2 backup
// archive, secrets in the clear. The rest of the old database (devices,
// sessions, Sends, invites, audit log) is converted into rows. What only
// lives for minutes (challenges, rate limits, used tokens, login requests)
// is left behind.
//
// Rows that cannot be carried over (their owner is gone, an id is not a
// uuid, ...) are left out and listed in the report.

export type LegacyRow = Record<string, unknown>;
export type LegacyTables = Partial<Record<string, LegacyRow[]>>;

export interface Report {
  skipped: Array<{ table: string; id: string; reason: string }>;
  // Things the operator has to know or do.
  notices: string[];
}

export interface ConvertedDatabase {
  snapshot: Snapshot;
  // Personal API keys in the clear. Backups never had them.
  apiKeys: Array<{ userId: string; key: string }>;
  devices: NewRow<'devices'>[];
  refreshTokens: NewRow<'refresh_tokens'>[];
  rememberTokens: NewRow<'two_factor_remember_tokens'>[];
  sends: NewRow<'sends'>[];
  invites: NewRow<'invites'>[];
  auditLogs: NewRow<'audit_logs'>[];
  // Settings that are the server's own, not backed up.
  pushInstallation: { id: string; key: string } | null;
  backupRuntime: { destinations: Record<string, unknown> } | null;
  // The backup settings in the clear, when the old JWT_SECRET opened them.
  backupSettings: string | null;
  report: Report;
}

// The old tables, parents first.
export const LEGACY_TABLES = [
  'config', 'users', 'user_revisions', 'domain_settings', 'webauthn_credentials', 'folders', 'organizations',
  'org_memberships', 'collections', 'collection_members', 'ciphers', 'cipher_collections', 'cipher_user_state',
  'attachments', 'devices', 'refresh_tokens', 'trusted_two_factor_device_tokens', 'sends', 'invites', 'audit_logs',
] as const;

// --- Values ------------------------------------------------------------------

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);

const text = (value: unknown): string | null => (value === null || value === undefined ? null : String(value));
const nonEmpty = (value: unknown): string | null => text(value)?.trim() || null;

function int(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : null;
}

// SQLite-era flags are 0/1, some were stored as text.
const bool = (value: unknown) => value === true || value === 1 || value === '1' || value === 't' || value === 'true';

// Times were ISO text in some tables and epoch milliseconds in others.
function ms(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = typeof value === 'number' ? value : /^\d+$/.test(String(value)) ? Number(value) : Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function time(value: unknown): string | null {
  const parsed = ms(value);
  return parsed === null ? null : new Date(parsed).toISOString();
}

function json(value: unknown): unknown {
  if (typeof value !== 'string') return value ?? null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);

// Tokens were stored as "sha256:<hex>" of the token; the oldest ones in the clear.
function tokenHash(stored: unknown): Buffer | null {
  const value = text(stored);
  if (!value) return null;
  if (!value.startsWith('sha256:')) return sha256(value);
  const hex = value.slice('sha256:'.length);
  return /^[0-9a-f]{64}$/i.test(hex) ? Buffer.from(hex, 'hex') : null;
}

// 32 base32 characters, in groups of four as they are shown.
function recoveryCode(value: unknown): string | null {
  const compact = String(value ?? '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  return compact ? compact.replace(/(.{4})(?!$)/g, '$1 ') : null;
}

// --- Settings ----------------------------------------------------------------

const LEGACY_BACKUP_SALT = 'nodewarden.backup-settings.runtime.v2';
const LEGACY_BACKUP_INFO = 'runtime';

// The old envelope: { version: 2, runtime: {iv, ciphertext}, portable }.
// Its runtime copy is keyed with JWT_SECRET; the portable one is the same
// as today's.
function legacyEnvelope(value: unknown): { runtime: { iv: string; ciphertext: string } | null; portable: Record<string, unknown> } | null {
  const envelope = json(value);
  if (!isObject(envelope) || Number(envelope.version) !== 2 || !isObject(envelope.portable)) return null;
  const { iv, ciphertext, wraps } = envelope.portable;
  if (typeof iv !== 'string' || typeof ciphertext !== 'string' || !Array.isArray(wraps)) return null;
  const runtime = isObject(envelope.runtime) && envelope.runtime.iv && envelope.runtime.ciphertext ? envelope.runtime : null;
  return { runtime: runtime as { iv: string; ciphertext: string } | null, portable: { iv, ciphertext, wraps } };
}

export function openLegacyBackupSettings(value: unknown, jwtSecret: string): string | null {
  const runtime = legacyEnvelope(value)?.runtime;
  if (!runtime || !jwtSecret) return null;
  try {
    const key = Buffer.from(hkdfSync('sha256', jwtSecret, LEGACY_BACKUP_SALT, LEGACY_BACKUP_INFO, 32));
    const sealed = Buffer.from(runtime.ciphertext, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(runtime.iv, 'base64'));
    decipher.setAuthTag(sealed.subarray(sealed.length - 16));
    return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

// Today's envelope without the runtime copy, as in an archive: an admin's
// client repairs it from the portable copy.
function portableEnvelope(value: unknown): string | null {
  const envelope = legacyEnvelope(value);
  return envelope ? JSON.stringify({ version: 3, runtime: null, portable: envelope.portable }) : null;
}

function convertSettings(config: Map<string, string>): VaultRecord[] {
  const settings: VaultRecord[] = [];
  const audit = json(config.get('audit.logs.settings.v1'));
  if (isObject(audit)) {
    settings.push({ key: 'audit.retention', value: { retentionDays: int(audit.retentionDays), maxEntries: int(audit.maxEntries) } });
  }
  const clientId = nonEmpty(config.get('globalSettings__yubico__clientId'));
  const secretKey = nonEmpty(config.get('globalSettings__yubico__key'));
  if (clientId && secretKey) settings.push({ key: 'yubico.credentials', value: { clientId, secretKey } });
  const backup = portableEnvelope(config.get('backup.settings.v1'));
  if (backup) settings.push({ key: 'backup.settings', value: backup });
  return settings;
}

// --- Accounts and vaults -----------------------------------------------------

class Conversion {
  readonly report: Report = { skipped: [], notices: [] };
  readonly now = Date.now();

  constructor(readonly tables: LegacyTables) {}

  rows(table: string): LegacyRow[] {
    return this.tables[table] ?? [];
  }

  skip(table: string, row: LegacyRow, reason: string, idColumn = 'id'): void {
    this.report.skipped.push({ table, id: String(row[idColumn] ?? '?'), reason });
  }
}

interface Owners {
  users: Map<string, VaultRecord>;
  folders: Map<string, string>;
  organizations: Set<string>;
  memberships: Set<string>;
  collections: Map<string, string>;
  ciphers: Map<string, VaultRecord>;
}

async function convertUsers(run: Conversion, snapshot: Snapshot, owners: Owners): Promise<void> {
  const revisions = new Map(run.rows('user_revisions').map((row) => [String(row.user_id), time(row.revision_date)]));
  const domains = new Map(run.rows('domain_settings').map((row) => [String(row.user_id), row]));
  const emails = new Set<string>();

  for (const row of run.rows('users')) {
    const id = String(row.id);
    const email = String(row.email ?? '').trim().toLowerCase();
    if (!isUuid(id)) { run.skip('users', row, 'the id is not a uuid'); continue; }
    if (!email || emails.has(email)) { run.skip('users', row, 'the email is missing or taken by another account'); continue; }
    const kdfType = int(row.kdf_type);
    const kdfIterations = int(row.kdf_iterations);
    if ((kdfType !== 0 && kdfType !== 1) || !kdfIterations || kdfIterations <= 0) { run.skip('users', row, 'the KDF settings are invalid'); continue; }
    emails.add(email);

    // The oldest accounts kept the client's hash as it was sent.
    const stored = String(row.master_password_hash ?? '');
    const masterPasswordHash = stored.startsWith('$s$') ? stored : await hashMasterPassword(stored, email);

    const domain = domains.get(id);
    const custom = normalizeCustomEquivalentDomains(json(domain?.custom_equivalent_domains));
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    const updatedAt = time(row.updated_at) ?? createdAt;
    const user: VaultRecord = {
      id,
      email,
      name: text(row.name),
      masterPasswordHash,
      masterPasswordHint: text(row.master_password_hint),
      key: String(row.key ?? ''),
      keyId: text(row.key_id),
      publicKey: text(row.public_key),
      privateKey: text(row.private_key),
      kdfType,
      kdfIterations,
      kdfMemory: int(row.kdf_memory),
      kdfParallelism: int(row.kdf_parallelism),
      securityStamp: String(row.security_stamp || randomUUID()),
      role: row.role === 'admin' ? 'admin' : 'user',
      status: row.status === 'banned' ? 'banned' : 'active',
      verifyDevices: bool(row.verify_devices),
      recoveryCode: recoveryCode(row.totp_recovery_code),
      // Early versions kept only the active groups.
      customDomains: custom.length ? custom : normalizeCustomEquivalentDomains(normalizeEquivalentDomains(json(domain?.equivalent_domains))),
      excludedGlobalDomains: normalizeExcludedGlobalTypes(json(domain?.excluded_global_equivalent_domains)),
      revisionDate: revisions.get(id) ?? updatedAt,
      createdAt,
      updatedAt,
    };
    snapshot.users.push(user);
    owners.users.set(id, user);

    const totp = nonEmpty(row.totp_secret);
    if (totp) snapshot.twoFactorProviders.push({ userId: id, type: 0, data: { secret: normalizeTotpSecret(totp) } });
    const keys = [1, 2, 3, 4, 5].map((slot) => nonEmpty(row[`yubikey_key${slot}`])?.replace(/\s+/g, '').toLowerCase() ?? null);
    if (keys.some(Boolean)) snapshot.twoFactorProviders.push({ userId: id, type: 3, data: { keys, nfc: bool(row.yubikey_nfc) } });
  }
}

function convertPasskeys(run: Conversion, snapshot: Snapshot, owners: Owners): void {
  const credentialIds = new Set<string>();
  // Security keys were numbered by their order.
  const slots = new Map<string, number>();
  const rows = [...run.rows('webauthn_credentials')].sort((a, b) => (ms(a.created_at) ?? 0) - (ms(b.created_at) ?? 0));
  for (const row of rows) {
    const userId = String(row.user_id);
    const credentialId = String(row.credential_id ?? '');
    if (!isUuid(row.id)) { run.skip('webauthn_credentials', row, 'the id is not a uuid'); continue; }
    if (!owners.users.has(userId)) { run.skip('webauthn_credentials', row, 'its user is gone'); continue; }
    if (!credentialId || credentialIds.has(credentialId)) { run.skip('webauthn_credentials', row, 'the credential id is missing or registered twice'); continue; }
    const purpose = row.purpose === 'twoFactor' ? 'twoFactor' : 'login';
    let slot: number | null = null;
    if (purpose === 'twoFactor') {
      slot = (slots.get(userId) ?? 0) + 1;
      if (slot > 5) { run.skip('webauthn_credentials', row, 'the user has more than five security keys'); continue; }
      slots.set(userId, slot);
    }
    credentialIds.add(credentialId);
    const transports = json(row.transports);
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    snapshot.passkeys.push({
      id: row.id,
      userId,
      purpose,
      slot,
      name: String(row.name ?? ''),
      credentialId,
      publicKey: String(row.public_key ?? ''),
      counter: int(row.counter) ?? 0,
      type: text(row.type),
      aaGuid: text(row.aa_guid),
      transports: Array.isArray(transports) ? transports.map(String) : null,
      supportsPrf: bool(row.supports_prf),
      encryptedUserKey: text(row.encrypted_user_key),
      encryptedPublicKey: text(row.encrypted_public_key),
      encryptedPrivateKey: text(row.encrypted_private_key),
      createdAt,
      updatedAt: time(row.updated_at) ?? createdAt,
    });
  }
}

function convertFolders(run: Conversion, snapshot: Snapshot, owners: Owners): void {
  for (const row of run.rows('folders')) {
    const userId = String(row.user_id);
    if (!isUuid(row.id)) { run.skip('folders', row, 'the id is not a uuid'); continue; }
    if (!owners.users.has(userId)) { run.skip('folders', row, 'its user is gone'); continue; }
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    snapshot.folders.push({ id: row.id, userId, name: String(row.name ?? ''), createdAt, updatedAt: time(row.updated_at) ?? createdAt });
    owners.folders.set(row.id, userId);
  }
}

function convertOrganizations(run: Conversion, snapshot: Snapshot, owners: Owners): void {
  for (const row of run.rows('organizations')) {
    if (!isUuid(row.id)) { run.skip('organizations', row, 'the id is not a uuid'); continue; }
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    snapshot.organizations.push({
      id: row.id,
      name: String(row.name ?? ''),
      billingEmail: String(row.billing_email ?? ''),
      publicKey: text(row.public_key),
      privateKey: text(row.private_key),
      createdAt,
      updatedAt: time(row.updated_at) ?? createdAt,
    });
    owners.organizations.add(row.id);
  }

  const members = new Set<string>();
  for (const row of run.rows('org_memberships')) {
    const organizationId = String(row.org_id);
    const userId = String(row.user_id);
    const status = int(row.status);
    const type = int(row.type);
    if (!isUuid(row.id)) { run.skip('org_memberships', row, 'the id is not a uuid'); continue; }
    if (!owners.organizations.has(organizationId) || !owners.users.has(userId)) { run.skip('org_memberships', row, 'its organization or user is gone'); continue; }
    if (members.has(`${organizationId}/${userId}`)) { run.skip('org_memberships', row, 'the user is a member twice'); continue; }
    if (status === null || status < -1 || status > 2 || type === null || type < 0 || type > 4) { run.skip('org_memberships', row, 'the status or type is invalid'); continue; }
    members.add(`${organizationId}/${userId}`);
    const revoked = int(row.revoked_status);
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    snapshot.memberships.push({
      id: row.id,
      organizationId,
      userId,
      status,
      type,
      accessAll: bool(row.access_all),
      key: text(row.akey),
      revokedStatus: revoked !== null && revoked >= 0 && revoked <= 2 ? revoked : null,
      invitedBy: owners.users.has(String(row.invited_by)) ? String(row.invited_by) : null,
      createdAt,
      updatedAt: time(row.updated_at) ?? createdAt,
    });
    owners.memberships.add(row.id);
  }

  for (const row of run.rows('collections')) {
    const organizationId = String(row.org_id);
    if (!isUuid(row.id)) { run.skip('collections', row, 'the id is not a uuid'); continue; }
    if (!owners.organizations.has(organizationId)) { run.skip('collections', row, 'its organization is gone'); continue; }
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    snapshot.collections.push({
      id: row.id,
      organizationId,
      name: String(row.name ?? ''),
      externalId: text(row.external_id),
      createdAt,
      updatedAt: time(row.updated_at) ?? createdAt,
    });
    owners.collections.set(row.id, organizationId);
  }

  const grants = new Set<string>();
  for (const row of run.rows('collection_members')) {
    const key = `${row.collection_id}/${row.membership_id}`;
    if (!owners.collections.has(String(row.collection_id)) || !owners.memberships.has(String(row.membership_id))) {
      run.skip('collection_members', row, 'its collection or member is gone', 'collection_id');
      continue;
    }
    if (grants.has(key)) continue;
    grants.add(key);
    snapshot.collectionGrants.push({
      collectionId: String(row.collection_id),
      membershipId: String(row.membership_id),
      readOnly: bool(row.read_only),
      hidePasswords: bool(row.hide_passwords),
      manage: bool(row.manage),
    });
  }
}

function convertCiphers(run: Conversion, snapshot: Snapshot, owners: Owners): void {
  // Where each user keeps a cipher. Organization ciphers had their own
  // table; personal ones kept it in their row.
  const states = new Map<string, VaultRecord>();
  const keepState = (cipherId: string, userId: string, folderId: string | null, favorite: boolean, archivedAt: string | null) => {
    const folder = folderId && owners.folders.get(folderId) === userId ? folderId : null;
    if (!folder && !favorite && !archivedAt) return;
    states.set(`${cipherId}/${userId}`, { cipherId, userId, folderId: folder, favorite, archivedAt });
  };

  for (const row of run.rows('ciphers')) {
    const userId = text(row.user_id);
    const organizationId = text(row.organization_id);
    const type = int(row.type);
    if (!isUuid(row.id)) { run.skip('ciphers', row, 'the id is not a uuid'); continue; }
    if (!userId === !organizationId) { run.skip('ciphers', row, 'it has no single owner'); continue; }
    if ((userId && !owners.users.has(userId)) || (organizationId && !owners.organizations.has(organizationId))) {
      run.skip('ciphers', row, 'its owner is gone');
      continue;
    }
    if (type === null || type < 1 || type > 8) { run.skip('ciphers', row, 'the type is unknown'); continue; }

    // Values some versions kept only in `data`, some with PascalCase keys.
    const raw = normalizeKeys(json(row.data));
    const stored = isObject(raw) ? raw : {};
    const name = text(row.name) ?? text(stored.name);
    if (!name) run.report.notices.push(`Cipher ${row.id} has no name; clients show it as an item without one.`);
    const data = JSON.parse(writeCipherData({ name: name ?? '', notes: text(row.notes) ?? text(stored.notes) }, readCipherData(stored)));
    if (!name) delete data.name;
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    const cipher: VaultRecord = {
      id: row.id,
      userId,
      organizationId,
      type,
      key: text(row.key) ?? text(stored.key),
      reprompt: int(row.reprompt ?? stored.reprompt) === 1 ? 1 : 0,
      data,
      createdAt,
      updatedAt: time(row.updated_at) ?? createdAt,
      deletedAt: time(row.deleted_at),
    };
    snapshot.ciphers.push(cipher);
    owners.ciphers.set(row.id, cipher);
    if (userId) {
      keepState(row.id, userId, text(row.folder_id) ?? text(stored.folderId), bool(row.favorite ?? stored.favorite), time(row.archived_at));
    }
  }

  for (const row of run.rows('cipher_user_state')) {
    const cipherId = String(row.cipher_id);
    const userId = String(row.user_id);
    if (!owners.ciphers.has(cipherId) || !owners.users.has(userId)) continue;
    keepState(cipherId, userId, text(row.folder_id), bool(row.favorite), time(row.archived_at));
  }
  snapshot.cipherStates.push(...states.values());

  const links = new Set<string>();
  for (const row of run.rows('cipher_collections')) {
    const cipher = owners.ciphers.get(String(row.cipher_id));
    const collectionOrg = owners.collections.get(String(row.collection_id));
    const key = `${row.cipher_id}/${row.collection_id}`;
    if (!cipher || !collectionOrg || cipher.organizationId !== collectionOrg || links.has(key)) continue;
    links.add(key);
    snapshot.cipherCollections.push({ cipherId: String(row.cipher_id), collectionId: String(row.collection_id) });
  }

  for (const row of run.rows('attachments')) {
    const cipher = owners.ciphers.get(String(row.cipher_id));
    const size = int(row.size);
    if (!isUuid(row.id)) { run.skip('attachments', row, 'the id is not a uuid'); continue; }
    if (!cipher) { run.skip('attachments', row, 'its cipher is gone'); continue; }
    if (size === null || size < 0) { run.skip('attachments', row, 'the size is invalid'); continue; }
    // The old table did not record when; the cipher's last change is close.
    snapshot.attachments.push({
      id: row.id,
      cipherId: String(row.cipher_id),
      fileName: String(row.file_name ?? ''),
      key: text(row.key),
      size,
      uploadedAt: cipher.updatedAt,
      createdAt: cipher.updatedAt,
    });
  }
}

async function convertVault(run: Conversion): Promise<{ snapshot: Snapshot; owners: Owners; config: Map<string, string> }> {
  const snapshot = Object.fromEntries(KIND_NAMES.map((kind) => [kind, []])) as unknown as Snapshot;
  const owners: Owners = {
    users: new Map(),
    folders: new Map(),
    organizations: new Set(),
    memberships: new Set(),
    collections: new Map(),
    ciphers: new Map(),
  };
  const config = new Map(run.rows('config').map((row) => [String(row.key), String(row.value ?? '')]));
  snapshot.settings = convertSettings(config);
  await convertUsers(run, snapshot, owners);
  convertPasskeys(run, snapshot, owners);
  convertFolders(run, snapshot, owners);
  convertOrganizations(run, snapshot, owners);
  convertCiphers(run, snapshot, owners);
  return { snapshot, owners, config };
}

// --- A v1 backup archive -----------------------------------------------------

// The tables of a v1 archive (db.json) as the records of a v2 one.
export async function convertBackupTables(tables: LegacyTables): Promise<{ snapshot: Snapshot; report: Report }> {
  const run = new Conversion(tables);
  const { snapshot } = await convertVault(run);
  if (snapshot.settings.some((setting) => setting.key === 'backup.settings')) {
    run.report.notices.push('The backup destinations need an admin to open Backups in the web vault once after the restore, as after any restore.');
  }
  return { snapshot, report: run.report };
}

// --- The old database --------------------------------------------------------

function convertDevices(run: Conversion, owners: Owners): Map<string, NewRow<'devices'>> {
  const devices = new Map<string, NewRow<'devices'>>();
  for (const row of run.rows('devices')) {
    const userId = String(row.user_id);
    const identifier = nonEmpty(row.device_identifier);
    if (!owners.users.has(userId) || !identifier) { run.skip('devices', row, 'its user is gone', 'device_identifier'); continue; }
    // A ban kept the device from signing in again. Devices can no longer be
    // banned; removing it ends its sessions all the same.
    if (bool(row.banned)) { run.skip('devices', row, 'it was banned; its sessions end', 'device_identifier'); continue; }
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    devices.set(`${userId}/${identifier}`, {
      id: randomUUID(),
      user_id: userId,
      identifier,
      name: String(row.name ?? ''),
      type: int(row.type) ?? 0,
      note: text(row.device_note),
      session_stamp: nonEmpty(row.session_stamp) ?? randomUUID(),
      push_uuid: isUuid(row.push_uuid) ? row.push_uuid : randomUUID(),
      push_token: nonEmpty(row.push_token),
      encrypted_user_key: text(row.encrypted_user_key),
      encrypted_public_key: text(row.encrypted_public_key),
      encrypted_private_key: text(row.encrypted_private_key),
      last_seen_at: time(row.last_seen_at),
      created_at: createdAt,
      updated_at: time(row.updated_at) ?? createdAt,
    });
  }
  return devices;
}

// Sessions carry over, so clients stay signed in. Each old token starts its
// own family. Old tokens left stamps empty until first used; they take the
// current ones, which is what their first use would have done.
function convertRefreshTokens(run: Conversion, owners: Owners, devices: Map<string, NewRow<'devices'>>): NewRow<'refresh_tokens'>[] {
  const tokens = new Map<string, NewRow<'refresh_tokens'>>();
  for (const row of run.rows('refresh_tokens')) {
    const user = owners.users.get(String(row.user_id));
    const hash = tokenHash(row.token);
    const skip = (reason: string) => run.report.skipped.push({ table: 'refresh_tokens', id: `user ${row.user_id}`, reason });
    if (!user || !hash) { skip('its user is gone or the token is malformed'); continue; }
    const created = ms(row.created_at) ?? run.now;
    const absolute = ms(row.absolute_expires_at) ?? created + LIMITS.auth.refreshTokenAbsoluteTtlMs;
    const expires = Math.min(ms(row.expires_at) ?? absolute, absolute);
    if (expires <= run.now) continue;
    const identifier = nonEmpty(row.device_identifier);
    const device = identifier ? devices.get(`${user.id}/${identifier}`) : undefined;
    if (identifier && !device) { skip('its device is gone'); continue; }
    const deviceStamp = nonEmpty(row.device_session_stamp) ?? device?.session_stamp ?? null;
    if (device && deviceStamp !== device.session_stamp) { skip('its device was signed out'); continue; }
    if ((nonEmpty(row.security_stamp) ?? user.securityStamp) !== user.securityStamp) { skip('the account was secured since'); continue; }
    tokens.set(hash.toString('hex'), {
      token_hash: hash,
      family_id: randomUUID(),
      user_id: String(user.id),
      device_id: device?.id ?? null,
      device_session_stamp: device ? deviceStamp : null,
      security_stamp: String(user.securityStamp),
      client_type: nonEmpty(row.client_type) ?? 'other',
      created_at: new Date(created).toISOString(),
      last_used_at: new Date(ms(row.last_used_at) ?? created).toISOString(),
      expires_at: new Date(expires).toISOString(),
      absolute_expires_at: new Date(absolute).toISOString(),
      rotated_at: null,
    });
  }
  return [...tokens.values()];
}

function convertRememberTokens(run: Conversion, owners: Owners): NewRow<'two_factor_remember_tokens'>[] {
  const tokens = new Map<string, NewRow<'two_factor_remember_tokens'>>();
  for (const row of run.rows('trusted_two_factor_device_tokens')) {
    const user = owners.users.get(String(row.user_id));
    const hash = tokenHash(row.token);
    const expires = ms(row.expires_at);
    const identifier = nonEmpty(row.device_identifier);
    if (!user || !hash || !identifier || !expires || expires <= run.now) continue;
    tokens.set(hash.toString('hex'), {
      token_hash: hash,
      user_id: String(user.id),
      device_identifier: identifier,
      security_stamp: String(user.securityStamp),
      expires_at: new Date(expires).toISOString(),
    });
  }
  return [...tokens.values()];
}

async function convertSends(run: Conversion, owners: Owners): Promise<NewRow<'sends'>[]> {
  const sends: NewRow<'sends'>[] = [];
  for (const row of run.rows('sends')) {
    const userId = String(row.user_id);
    const type = int(row.type);
    const deletionDate = time(row.deletion_date);
    if (!isUuid(row.id)) { run.skip('sends', row, 'the id is not a uuid'); continue; }
    if (!owners.users.has(userId)) { run.skip('sends', row, 'its user is gone'); continue; }
    if ((type !== 0 && type !== 1) || !deletionDate) { run.skip('sends', row, 'the type or deletion date is invalid'); continue; }
    if (ms(deletionDate)! <= run.now) continue;

    const stored = json(row.data);
    const data = isObject(normalizeKeys(stored)) ? (normalizeKeys(stored) as Record<string, unknown>) : {};
    const file = type === 1 && isObject(data) ? { id: String(data.id ?? ''), fileName: String(data.fileName ?? ''), size: int(data.size) ?? 0 } : null;
    const sendText = type === 0 ? { text: text(data.text), hidden: bool(data.hidden) } : null;

    // Passwords were kept either salted by the server, or as the hash the
    // client sent; the latter are salted now.
    let password: { hash: string; salt: string; iterations: number } | null = null;
    const hash = nonEmpty(row.password_hash);
    if (hash && nonEmpty(row.password_salt) && int(row.password_iterations)) {
      password = { hash, salt: String(row.password_salt), iterations: int(row.password_iterations)! };
    } else if (hash) {
      password = await hashSendPassword(hash);
    }
    // Email verification was never supported; such a Send is switched off
    // rather than opened to anyone with the link.
    const emailOnly = int(row.auth_type) === 0 && !password;
    if (emailOnly) run.report.notices.push(`Send ${row.id} was limited to email addresses, which is not supported; it is disabled.`);

    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    sends.push({
      id: row.id,
      user_id: userId,
      type,
      key: String(row.key ?? ''),
      data: JSON.stringify({ name: String(row.name ?? ''), notes: text(row.notes), text: sendText, file }),
      password_hash: password?.hash ?? null,
      password_salt: password?.salt ?? null,
      password_iterations: password?.iterations ?? null,
      max_access_count: int(row.max_access_count),
      access_count: int(row.access_count) ?? 0,
      disabled: bool(row.disabled) || emailOnly,
      hide_email: bool(row.hide_email),
      created_at: createdAt,
      updated_at: time(row.updated_at) ?? createdAt,
      expiration_date: time(row.expiration_date),
      deletion_date: deletionDate,
    });
  }
  return sends;
}

function convertInvites(run: Conversion, owners: Owners): NewRow<'invites'>[] {
  const invites: NewRow<'invites'>[] = [];
  for (const row of run.rows('invites')) {
    const status = row.status === 'used' ? 'used' : row.status === 'active' ? 'active' : null;
    const createdBy = String(row.created_by);
    if (!status) continue;
    if (!owners.users.has(createdBy)) { run.skip('invites', row, 'its creator is gone', 'code'); continue; }
    const createdAt = time(row.created_at) ?? new Date(run.now).toISOString();
    invites.push({
      code: String(row.code),
      created_by: createdBy,
      used_by: owners.users.has(String(row.used_by)) ? String(row.used_by) : null,
      status,
      expires_at: time(row.expires_at) ?? createdAt,
      created_at: createdAt,
      updated_at: time(row.updated_at) ?? createdAt,
    });
  }
  return invites;
}

function convertAuditLogs(run: Conversion, owners: Owners): NewRow<'audit_logs'>[] {
  const logs: NewRow<'audit_logs'>[] = [];
  for (const row of run.rows('audit_logs')) {
    if (!isUuid(row.id)) { run.skip('audit_logs', row, 'the id is not a uuid'); continue; }
    const metadata = json(row.metadata);
    logs.push({
      id: row.id,
      actor_user_id: owners.users.has(String(row.actor_user_id)) ? String(row.actor_user_id) : null,
      action: String(row.action ?? ''),
      category: nonEmpty(row.category) ?? 'system',
      level: nonEmpty(row.level) ?? 'info',
      target_type: text(row.target_type),
      target_id: text(row.target_id),
      metadata: isObject(metadata) ? JSON.stringify(metadata) : null,
      created_at: time(row.created_at) ?? new Date(run.now).toISOString(),
    });
  }
  return logs;
}

export async function convertDatabase(tables: LegacyTables, options: { jwtSecret: string }): Promise<ConvertedDatabase> {
  const run = new Conversion(tables);
  const { snapshot, owners, config } = await convertVault(run);

  const apiKeys: ConvertedDatabase['apiKeys'] = [];
  for (const row of run.rows('users')) {
    const key = nonEmpty(row.api_key);
    if (!key || !owners.users.has(String(row.id))) continue;
    // Only a hash of these was kept; the owner has to issue a new key.
    if (key.startsWith('sha256:')) run.report.notices.push(`${row.email}: the API key has to be issued again (Settings > Security > Keys).`);
    else apiKeys.push({ userId: String(row.id), key });
  }

  const devices = convertDevices(run, owners);
  const pushId = nonEmpty(config.get('push.installation.id'));
  const pushKey = nonEmpty(config.get('push.installation.key'));
  const runtime = json(config.get('backup.runtime.v1'));

  const backupSettings = openLegacyBackupSettings(config.get('backup.settings.v1'), options.jwtSecret);
  if (config.has('backup.settings.v1') && !backupSettings) {
    run.report.notices.push(
      'The backup settings could not be opened with JWT_SECRET. An admin has to open Backups in the web vault once to repair them.',
    );
  }

  return {
    snapshot,
    apiKeys,
    devices: [...devices.values()],
    refreshTokens: convertRefreshTokens(run, owners, devices),
    rememberTokens: convertRememberTokens(run, owners),
    sends: await convertSends(run, owners),
    invites: convertInvites(run, owners),
    auditLogs: convertAuditLogs(run, owners),
    pushInstallation: pushId && pushKey ? { id: pushId, key: pushKey } : null,
    backupRuntime: isObject(runtime) && isObject(runtime.destinations) ? { destinations: runtime.destinations } : null,
    backupSettings: backupSettings === null ? null : storedSettings(parseStoredSettings(backupSettings)),
    report: run.report,
  };
}
