// IMPORTANT:
// This is the runtime PostgreSQL schema bootstrap. It is the single source of
// truth for the database layout (there is no separate migrations directory).
//
// WHEN CHANGING THIS:
// - Bump STORAGE_SCHEMA_VERSION in src/services/storage.ts so existing installs
//   rerun these idempotent statements.
// - Add new columns to existing tables with `ALTER TABLE ... ADD COLUMN IF NOT
//   EXISTS` below the CREATE TABLE, never by editing an already shipped CREATE.
// - If the new table stores persistent data, update the backup export/import
//   contract in src/services/backup-archive.ts and backup-import.ts.
// - Integer columns are BIGINT: several of them hold millisecond timestamps.
const SCHEMA_STATEMENTS: readonly string[] = [
  'CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)',

  'CREATE TABLE IF NOT EXISTS users (' +
  'id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hint TEXT, master_password_hash TEXT NOT NULL, ' +
  'key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type BIGINT NOT NULL, ' +
  'kdf_iterations BIGINT NOT NULL, kdf_memory BIGINT, kdf_parallelism BIGINT, ' +
  'security_stamp TEXT NOT NULL, role TEXT NOT NULL DEFAULT \'user\', status TEXT NOT NULL DEFAULT \'active\', verify_devices BIGINT NOT NULL DEFAULT 0, totp_secret TEXT, totp_recovery_code TEXT, yubikey_key1 TEXT, yubikey_key2 TEXT, yubikey_key3 TEXT, yubikey_key4 TEXT, yubikey_key5 TEXT, yubikey_nfc BIGINT NOT NULL DEFAULT 0, api_key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',

  'CREATE TABLE IF NOT EXISTS domain_settings (' +
  'user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, equivalent_domains TEXT NOT NULL DEFAULT \'[]\', custom_equivalent_domains TEXT NOT NULL DEFAULT \'[]\', excluded_global_equivalent_domains TEXT NOT NULL DEFAULT \'[]\', updated_at TEXT NOT NULL)',

  'CREATE TABLE IF NOT EXISTS user_revisions (' +
  'user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, revision_date TEXT NOT NULL)',

  // Organizations (sharing). Keys are end-to-end encrypted by clients: the
  // server only stores the org key wrapped for each member (org_memberships.akey)
  // and the org's own RSA key pair (private key encrypted with the org key).
  'CREATE TABLE IF NOT EXISTS organizations (' +
  'id TEXT PRIMARY KEY, name TEXT NOT NULL, billing_email TEXT NOT NULL, public_key TEXT, private_key TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',

  // status: -1 revoked (see ORG_MEMBER_STATUS), 0 invited, 1 accepted, 2 confirmed.
  // type: 0 owner, 1 admin, 2 user, 3 manager.
  // revoked_status keeps the pre-revocation status so restore can return to it.
  'CREATE TABLE IF NOT EXISTS org_memberships (' +
  'id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, ' +
  'user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, ' +
  'status BIGINT NOT NULL, type BIGINT NOT NULL, access_all BIGINT NOT NULL DEFAULT 0, akey TEXT, ' +
  'revoked_status BIGINT, invited_by TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'UNIQUE (org_id, user_id))',
  'CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships(user_id)',

  'CREATE TABLE IF NOT EXISTS collections (' +
  'id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, ' +
  'name TEXT NOT NULL, external_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(org_id)',

  'CREATE TABLE IF NOT EXISTS collection_members (' +
  'collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE, ' +
  'membership_id TEXT NOT NULL REFERENCES org_memberships(id) ON DELETE CASCADE, ' +
  'read_only BIGINT NOT NULL DEFAULT 0, hide_passwords BIGINT NOT NULL DEFAULT 0, manage BIGINT NOT NULL DEFAULT 0, ' +
  'PRIMARY KEY (collection_id, membership_id))',
  'CREATE INDEX IF NOT EXISTS idx_collection_members_membership ON collection_members(membership_id)',

  // A cipher is owned by exactly one of: a user (personal vault) or an organization.
  'CREATE TABLE IF NOT EXISTS ciphers (' +
  'id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE, ' +
  'organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE, type BIGINT NOT NULL, folder_id TEXT, name TEXT, notes TEXT, ' +
  'favorite BIGINT NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt BIGINT, key TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT, deleted_at TEXT, ' +
  'CONSTRAINT ciphers_single_owner CHECK ((user_id IS NULL) <> (organization_id IS NULL)))',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_org_updated ON ciphers(organization_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS cipher_collections (' +
  'cipher_id TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE, ' +
  'collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE, ' +
  'PRIMARY KEY (cipher_id, collection_id))',
  'CREATE INDEX IF NOT EXISTS idx_cipher_collections_collection ON cipher_collections(collection_id)',

  // Per-user view state of organization ciphers (folder, favorite, archive).
  // Personal ciphers keep these on the ciphers row.
  'CREATE TABLE IF NOT EXISTS cipher_user_state (' +
  'cipher_id TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE, ' +
  'user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, ' +
  'folder_id TEXT, favorite BIGINT NOT NULL DEFAULT 0, archived_at TEXT, ' +
  'PRIMARY KEY (cipher_id, user_id))',
  'CREATE INDEX IF NOT EXISTS idx_cipher_user_state_user ON cipher_user_state(user_id)',

  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_updated ON ciphers(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_archived ON ciphers(user_id, archived_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted ON ciphers(user_id, deleted_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted_updated ON ciphers(user_id, deleted_at, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_folder ON ciphers(user_id, folder_id)',

  'CREATE TABLE IF NOT EXISTS folders (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_folders_user_updated ON folders(user_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS attachments (' +
  'id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE, file_name TEXT NOT NULL, size BIGINT NOT NULL, ' +
  'size_name TEXT NOT NULL, key TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id)',

  'CREATE TABLE IF NOT EXISTS sends (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type BIGINT NOT NULL, name TEXT NOT NULL, notes TEXT, data TEXT NOT NULL, ' +
  'key TEXT NOT NULL, password_hash TEXT, password_salt TEXT, password_iterations BIGINT, auth_type BIGINT NOT NULL DEFAULT 2, emails TEXT, ' +
  'max_access_count BIGINT, access_count BIGINT NOT NULL DEFAULT 0, disabled BIGINT NOT NULL DEFAULT 0, hide_email BIGINT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expiration_date TEXT, deletion_date TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_updated ON sends(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_deletion ON sends(user_id, deletion_date)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_updated_id ON sends(user_id, updated_at, id)',

  'CREATE TABLE IF NOT EXISTS refresh_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at BIGINT NOT NULL, device_identifier TEXT, device_session_stamp TEXT, security_stamp TEXT, created_at BIGINT, last_used_at BIGINT, absolute_expires_at BIGINT, client_type TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)',

  'CREATE TABLE IF NOT EXISTS invites (' +
  'code TEXT PRIMARY KEY, created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, used_by TEXT REFERENCES users(id) ON DELETE SET NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_invites_status_expires ON invites(status, expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by, created_at)',

  'CREATE TABLE IF NOT EXISTS audit_logs (' +
  'id TEXT PRIMARY KEY, actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL, category TEXT NOT NULL DEFAULT \'system\', level TEXT NOT NULL DEFAULT \'info\', target_type TEXT, target_id TEXT, metadata TEXT, created_at TEXT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_category_created ON audit_logs(category, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_level_created ON audit_logs(level, created_at)',

  'CREATE TABLE IF NOT EXISTS devices (' +
  'user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_identifier TEXT NOT NULL, name TEXT NOT NULL, type BIGINT NOT NULL, session_stamp TEXT, encrypted_user_key TEXT, encrypted_public_key TEXT, encrypted_private_key TEXT, push_uuid TEXT, push_token TEXT, banned BIGINT NOT NULL DEFAULT 0, banned_at TEXT, device_note TEXT, last_seen_at TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'PRIMARY KEY (user_id, device_identifier))',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_updated ON devices(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen ON devices(user_id, last_seen_at)',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_push ON devices(user_id, push_token)',

  'CREATE TABLE IF NOT EXISTS auth_requests (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, organization_id TEXT, type BIGINT NOT NULL, request_device_identifier TEXT NOT NULL, request_device_type BIGINT NOT NULL, ' +
  'request_ip_address TEXT, request_country_name TEXT, response_device_identifier TEXT, access_code TEXT NOT NULL, public_key TEXT NOT NULL, key TEXT, master_password_hash TEXT, ' +
  'approved BIGINT, creation_date TEXT NOT NULL, response_date TEXT, authentication_date TEXT)',
  'CREATE INDEX IF NOT EXISTS idx_auth_requests_user_created ON auth_requests(user_id, creation_date)',
  'CREATE INDEX IF NOT EXISTS idx_auth_requests_user_pending ON auth_requests(user_id, approved, response_date, authentication_date, creation_date)',
  'CREATE INDEX IF NOT EXISTS idx_auth_requests_device_pending ON auth_requests(user_id, request_device_identifier, creation_date)',

  'CREATE TABLE IF NOT EXISTS trusted_two_factor_device_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_identifier TEXT NOT NULL, expires_at BIGINT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_trusted_two_factor_device_tokens_user_device ON trusted_two_factor_device_tokens(user_id, device_identifier)',

  'CREATE TABLE IF NOT EXISTS totp_login_replays (' +
  'user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, time_counter BIGINT NOT NULL, consumed_at BIGINT NOT NULL, ' +
  'PRIMARY KEY (user_id, time_counter))',
  'CREATE INDEX IF NOT EXISTS idx_totp_login_replays_consumed_at ON totp_login_replays(consumed_at)',

  'CREATE TABLE IF NOT EXISTS webauthn_credentials (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, purpose TEXT NOT NULL DEFAULT \'login\', name TEXT NOT NULL, public_key TEXT NOT NULL, credential_id TEXT NOT NULL, counter BIGINT NOT NULL DEFAULT 0, ' +
  'type TEXT, aa_guid TEXT, transports TEXT, encrypted_user_key TEXT, encrypted_public_key TEXT, encrypted_private_key TEXT, supports_prf BIGINT NOT NULL DEFAULT 0, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_updated ON webauthn_credentials(user_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS webauthn_challenges (' +
  'challenge_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, user_id TEXT, expires_at BIGINT NOT NULL, used_at BIGINT, created_at BIGINT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_scope ON webauthn_challenges(user_id, scope)',

  'CREATE TABLE IF NOT EXISTS login_attempts_ip (' +
  'ip TEXT PRIMARY KEY, attempts BIGINT NOT NULL, locked_until BIGINT, updated_at BIGINT NOT NULL)',

  // Short-lived counters: UNLOGGED skips WAL writes, losing them on a crash is fine.
  'CREATE UNLOGGED TABLE IF NOT EXISTS rate_limit_buckets (' +
  'bucket_key TEXT PRIMARY KEY, count BIGINT NOT NULL, expires_at BIGINT NOT NULL, updated_at BIGINT NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires ON rate_limit_buckets(expires_at)',

  'CREATE TABLE IF NOT EXISTS used_attachment_download_tokens (' +
  'jti TEXT PRIMARY KEY, expires_at BIGINT NOT NULL)',
];

// Arbitrary constant key for pg_advisory_xact_lock so concurrent cold starts
// do not race each other through CREATE TABLE IF NOT EXISTS.
const SCHEMA_LOCK_KEY = 7_302_914_551;

async function ensureAdminUserExists(db: D1Database): Promise<void> {
  const admin = await db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").first<{ id: string }>();
  if (admin?.id) return;

  const firstUser = await db
    .prepare('SELECT id FROM users ORDER BY created_at ASC LIMIT 1')
    .first<{ id: string }>();
  if (!firstUser?.id) return;

  await db
    .prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), firstUser.id)
    .run();
}

export const REQUIRED_SCHEMA_TABLE_NAMES = [
  'users',
  'organizations',
  'org_memberships',
  'collections',
  'collection_members',
  'cipher_collections',
  'cipher_user_state',
  'ciphers',
  'folders',
  'attachments',
  'sends',
  'refresh_tokens',
  'devices',
  'config',
] as const;

export async function ensureStorageSchema(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare(`SELECT pg_advisory_xact_lock(${SCHEMA_LOCK_KEY})`),
    ...SCHEMA_STATEMENTS.map((statement) => db.prepare(statement)),
  ]);
  await ensureAdminUserExists(db);
}
