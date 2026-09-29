import { sql, type Kysely } from 'kysely';

// The schema MoliWarden starts from. Ids are uuids, times timestamptz,
// flags boolean; everything a client encrypts is opaque text, or jsonb when
// it is a structure the server never looks into.

const STATEMENTS = [
  // Server state that is not an account's: backup settings, audit log
  // retention, Yubico and push relay credentials.
  `CREATE TABLE settings (
    key text PRIMARY KEY,
    value jsonb NOT NULL
  )`,

  // Named locks for jobs that must not run twice at once (see lease.ts).
  `CREATE TABLE job_leases (
    name text PRIMARY KEY,
    token uuid NOT NULL,
    expires_at timestamptz NOT NULL
  )`,

  `CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE CHECK (email = lower(email)),
    name text,
    master_password_hash text NOT NULL,
    master_password_hint text,
    key text NOT NULL,
    key_id text,
    public_key text,
    private_key text,
    kdf_type smallint NOT NULL CHECK (kdf_type IN (0, 1)),
    kdf_iterations integer NOT NULL CHECK (kdf_iterations > 0),
    kdf_memory integer,
    kdf_parallelism integer,
    security_stamp text NOT NULL,
    role text NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'banned')),
    verify_devices boolean NOT NULL DEFAULT false,
    api_key text,
    recovery_code text,
    custom_domains jsonb NOT NULL DEFAULT '[]',
    excluded_global_domains integer[] NOT NULL DEFAULT '{}',
    -- When anything the user syncs last changed.
    revision_date timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  )`,

  // Authenticator app (0) and YubiKey OTP (3). Security keys are
  // webauthn_credentials.
  `CREATE TABLE two_factor_providers (
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    type smallint NOT NULL CHECK (type IN (0, 3)),
    data jsonb NOT NULL,
    PRIMARY KEY (user_id, type)
  )`,

  `CREATE TABLE two_factor_remember_tokens (
    token_hash bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    device_identifier text NOT NULL,
    security_stamp text NOT NULL,
    expires_at timestamptz NOT NULL
  )`,
  'CREATE INDEX two_factor_remember_tokens_user ON two_factor_remember_tokens (user_id, device_identifier)',

  // The identifier is the client's own and is what clients call the device's id.
  `CREATE TABLE devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    identifier text NOT NULL,
    name text NOT NULL,
    type smallint NOT NULL,
    note text,
    session_stamp text NOT NULL,
    push_uuid uuid NOT NULL,
    push_token text,
    encrypted_user_key text,
    encrypted_public_key text,
    encrypted_private_key text,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (user_id, identifier)
  )`,

  // Each refresh replaces the token with a new one of the same family.
  `CREATE TABLE refresh_tokens (
    token_hash bytea PRIMARY KEY,
    family_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    device_id uuid REFERENCES devices ON DELETE CASCADE,
    device_session_stamp text,
    security_stamp text NOT NULL,
    client_type text NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    rotated_at timestamptz
  )`,
  'CREATE INDEX refresh_tokens_family ON refresh_tokens (family_id)',
  'CREATE INDEX refresh_tokens_user ON refresh_tokens (user_id)',
  'CREATE INDEX refresh_tokens_device ON refresh_tokens (device_id)',
  'CREATE INDEX refresh_tokens_expires ON refresh_tokens (expires_at)',

  // Login passkeys, and security keys for two-step login (slots 1-5).
  `CREATE TABLE webauthn_credentials (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('login', 'twoFactor')),
    slot smallint CHECK (slot BETWEEN 1 AND 5),
    name text NOT NULL,
    credential_id text NOT NULL UNIQUE,
    public_key text NOT NULL,
    counter bigint NOT NULL DEFAULT 0,
    type text,
    aa_guid text,
    transports text[],
    supports_prf boolean NOT NULL DEFAULT false,
    encrypted_user_key text,
    encrypted_public_key text,
    encrypted_private_key text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  )`,
  'CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id, purpose)',

  `CREATE TABLE webauthn_challenges (
    challenge_hash bytea PRIMARY KEY,
    scope text NOT NULL,
    user_id uuid REFERENCES users ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
  )`,
  'CREATE INDEX webauthn_challenges_expires ON webauthn_challenges (expires_at)',

  // Single-use tokens that were used: download links, authenticator codes.
  `CREATE TABLE consumed_tokens (
    key text PRIMARY KEY,
    expires_at timestamptz NOT NULL
  )`,
  'CREATE INDEX consumed_tokens_expires ON consumed_tokens (expires_at)',

  // Request counters. Losing them in a crash is harmless, so no WAL.
  `CREATE UNLOGGED TABLE rate_limits (
    key text PRIMARY KEY,
    count integer NOT NULL,
    expires_at timestamptz NOT NULL
  )`,
  'CREATE INDEX rate_limits_expires ON rate_limits (expires_at)',

  `CREATE TABLE login_failures (
    key text PRIMARY KEY,
    failures integer NOT NULL,
    locked_until timestamptz,
    updated_at timestamptz NOT NULL
  )`,

  `CREATE TABLE folders (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  )`,
  'CREATE INDEX folders_user ON folders (user_id)',

  `CREATE TABLE organizations (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    billing_email text NOT NULL,
    public_key text,
    private_key text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  )`,

  // status: -1 revoked, 0 invited, 1 accepted, 2 confirmed.
  // type: 0 owner, 1 admin, 2 user, 3 manager, 4 custom.
  // key: the organization key, encrypted for the member.
  `CREATE TABLE memberships (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    status smallint NOT NULL CHECK (status BETWEEN -1 AND 2),
    type smallint NOT NULL CHECK (type BETWEEN 0 AND 4),
    access_all boolean NOT NULL DEFAULT false,
    key text,
    revoked_status smallint CHECK (revoked_status BETWEEN 0 AND 2),
    invited_by uuid REFERENCES users ON DELETE SET NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (organization_id, user_id)
  )`,
  'CREATE INDEX memberships_user ON memberships (user_id)',

  `CREATE TABLE collections (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations ON DELETE CASCADE,
    name text NOT NULL,
    external_id text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  )`,
  'CREATE INDEX collections_organization ON collections (organization_id)',

  `CREATE TABLE collection_grants (
    collection_id uuid NOT NULL REFERENCES collections ON DELETE CASCADE,
    membership_id uuid NOT NULL REFERENCES memberships ON DELETE CASCADE,
    read_only boolean NOT NULL DEFAULT false,
    hide_passwords boolean NOT NULL DEFAULT false,
    manage boolean NOT NULL DEFAULT false,
    PRIMARY KEY (collection_id, membership_id)
  )`,
  'CREATE INDEX collection_grants_membership ON collection_grants (membership_id)',

  // Owned by a user (their vault) or by an organization, never both.
  // data holds the encrypted fields: name, notes, login, card, ...
  `CREATE TABLE ciphers (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES users ON DELETE CASCADE,
    organization_id uuid REFERENCES organizations ON DELETE CASCADE,
    type smallint NOT NULL CHECK (type BETWEEN 1 AND 8),
    key text,
    reprompt smallint NOT NULL DEFAULT 0 CHECK (reprompt IN (0, 1)),
    data jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CHECK ((user_id IS NULL) <> (organization_id IS NULL))
  )`,
  'CREATE INDEX ciphers_user ON ciphers (user_id)',
  'CREATE INDEX ciphers_organization ON ciphers (organization_id)',

  `CREATE TABLE cipher_collections (
    cipher_id uuid NOT NULL REFERENCES ciphers ON DELETE CASCADE,
    collection_id uuid NOT NULL REFERENCES collections ON DELETE CASCADE,
    PRIMARY KEY (cipher_id, collection_id)
  )`,
  'CREATE INDEX cipher_collections_collection ON cipher_collections (collection_id)',

  // Where each user keeps a cipher: folder, favorite, archive.
  `CREATE TABLE cipher_user_state (
    cipher_id uuid NOT NULL REFERENCES ciphers ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    folder_id uuid REFERENCES folders ON DELETE SET NULL,
    favorite boolean NOT NULL DEFAULT false,
    archived_at timestamptz,
    PRIMARY KEY (cipher_id, user_id)
  )`,
  'CREATE INDEX cipher_user_state_user ON cipher_user_state (user_id)',
  'CREATE INDEX cipher_user_state_folder ON cipher_user_state (folder_id)',

  // The file is in blob storage as <cipher_id>/<id> once uploaded_at is set.
  `CREATE TABLE attachments (
    id uuid PRIMARY KEY,
    cipher_id uuid NOT NULL REFERENCES ciphers ON DELETE CASCADE,
    file_name text NOT NULL,
    key text,
    size bigint NOT NULL CHECK (size >= 0),
    uploaded_at timestamptz,
    created_at timestamptz NOT NULL
  )`,
  'CREATE INDEX attachments_cipher ON attachments (cipher_id)',
  'CREATE INDEX attachments_pending ON attachments (created_at) WHERE uploaded_at IS NULL',

  // data holds the encrypted fields: name, notes, and the text or file.
  `CREATE TABLE sends (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    type smallint NOT NULL CHECK (type IN (0, 1)),
    key text NOT NULL,
    data jsonb NOT NULL,
    password_hash text,
    password_salt text,
    password_iterations integer,
    max_access_count integer,
    access_count integer NOT NULL DEFAULT 0,
    disabled boolean NOT NULL DEFAULT false,
    hide_email boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expiration_date timestamptz,
    deletion_date timestamptz NOT NULL,
    CHECK ((password_hash IS NULL) = (password_salt IS NULL))
  )`,
  'CREATE INDEX sends_user ON sends (user_id)',
  'CREATE INDEX sends_deletion ON sends (deletion_date)',

  // type: 0 login and unlock, 1 unlock, 2 admin approval.
  `CREATE TABLE auth_requests (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    type smallint NOT NULL CHECK (type BETWEEN 0 AND 2),
    request_device_identifier text NOT NULL,
    request_device_type smallint NOT NULL,
    request_ip_address text,
    request_country_name text,
    response_device_identifier text,
    access_code text NOT NULL,
    public_key text NOT NULL,
    key text,
    approved boolean,
    created_at timestamptz NOT NULL,
    responded_at timestamptz,
    authenticated_at timestamptz
  )`,
  'CREATE INDEX auth_requests_user ON auth_requests (user_id, created_at)',

  `CREATE TABLE invites (
    code text PRIMARY KEY,
    created_by uuid NOT NULL REFERENCES users ON DELETE CASCADE,
    used_by uuid REFERENCES users ON DELETE SET NULL,
    status text NOT NULL CHECK (status IN ('active', 'used')),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
  )`,

  `CREATE TABLE audit_logs (
    id uuid PRIMARY KEY,
    actor_user_id uuid REFERENCES users ON DELETE SET NULL,
    action text NOT NULL,
    category text NOT NULL,
    level text NOT NULL,
    target_type text,
    target_id text,
    metadata jsonb,
    created_at timestamptz NOT NULL
  )`,
  'CREATE INDEX audit_logs_created ON audit_logs (created_at)',
];

export async function up(db: Kysely<unknown>): Promise<void> {
  for (const statement of STATEMENTS) await sql.raw(statement).execute(db);
}
