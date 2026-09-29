import type { ColumnType, Insertable, Selectable, Updateable } from 'kysely';

// The tables as they exist today (created by src/services/storage-schema.ts).
// Timestamps are ISO strings or epoch milliseconds, flags are 0/1 BIGINTs:
// the repositories translate at the boundary, so the services never see it.

type Flag = ColumnType<number, number | undefined, number>;

export interface ConfigTable {
  key: string;
  value: string;
}

export interface UsersTable {
  id: string;
  email: string;
  name: string | null;
  master_password_hint: string | null;
  master_password_hash: string;
  key: string;
  private_key: string | null;
  public_key: string | null;
  kdf_type: number;
  kdf_iterations: number;
  kdf_memory: number | null;
  kdf_parallelism: number | null;
  security_stamp: string;
  role: ColumnType<string, string | undefined, string>;
  status: ColumnType<string, string | undefined, string>;
  verify_devices: Flag;
  totp_secret: string | null;
  totp_recovery_code: string | null;
  yubikey_key1: string | null;
  yubikey_key2: string | null;
  yubikey_key3: string | null;
  yubikey_key4: string | null;
  yubikey_key5: string | null;
  yubikey_nfc: Flag;
  api_key: string | null;
  key_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface DomainSettingsTable {
  user_id: string;
  equivalent_domains: ColumnType<string, string | undefined, string>;
  custom_equivalent_domains: ColumnType<string, string | undefined, string>;
  excluded_global_equivalent_domains: ColumnType<string, string | undefined, string>;
  updated_at: string;
}

export interface UserRevisionsTable {
  user_id: string;
  revision_date: string;
}

export interface OrganizationsTable {
  id: string;
  name: string;
  billing_email: string;
  public_key: string | null;
  private_key: string | null;
  created_at: string;
  updated_at: string;
}

export interface OrgMembershipsTable {
  id: string;
  org_id: string;
  user_id: string;
  status: number;
  type: number;
  access_all: Flag;
  akey: string | null;
  revoked_status: number | null;
  invited_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface CollectionsTable {
  id: string;
  org_id: string;
  name: string;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface CollectionMembersTable {
  collection_id: string;
  membership_id: string;
  read_only: Flag;
  hide_passwords: Flag;
  manage: Flag;
}

export interface CiphersTable {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  type: number;
  folder_id: string | null;
  name: string | null;
  notes: string | null;
  favorite: Flag;
  data: string;
  reprompt: number | null;
  key: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  deleted_at: string | null;
}

export interface CipherCollectionsTable {
  cipher_id: string;
  collection_id: string;
}

export interface CipherUserStateTable {
  cipher_id: string;
  user_id: string;
  folder_id: string | null;
  favorite: Flag;
  archived_at: string | null;
}

export interface FoldersTable {
  id: string;
  user_id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface AttachmentsTable {
  id: string;
  cipher_id: string;
  file_name: string;
  size: number;
  size_name: string;
  key: string | null;
}

export interface SendsTable {
  id: string;
  user_id: string;
  type: number;
  name: string;
  notes: string | null;
  data: string;
  key: string;
  password_hash: string | null;
  password_salt: string | null;
  password_iterations: number | null;
  auth_type: ColumnType<number, number | undefined, number>;
  emails: string | null;
  max_access_count: number | null;
  access_count: ColumnType<number, number | undefined, number>;
  disabled: Flag;
  hide_email: number | null;
  created_at: string;
  updated_at: string;
  expiration_date: string | null;
  deletion_date: string;
}

export interface RefreshTokensTable {
  token: string;
  user_id: string;
  expires_at: number;
  device_identifier: string | null;
  device_session_stamp: string | null;
  security_stamp: string | null;
  created_at: number | null;
  last_used_at: number | null;
  absolute_expires_at: number | null;
  client_type: string | null;
}

export interface InvitesTable {
  code: string;
  created_by: string;
  used_by: string | null;
  expires_at: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface AuditLogsTable {
  id: string;
  actor_user_id: string | null;
  action: string;
  category: ColumnType<string, string | undefined, string>;
  level: ColumnType<string, string | undefined, string>;
  target_type: string | null;
  target_id: string | null;
  metadata: string | null;
  created_at: string;
}

export interface DevicesTable {
  user_id: string;
  device_identifier: string;
  name: string;
  type: number;
  session_stamp: string | null;
  encrypted_user_key: string | null;
  encrypted_public_key: string | null;
  encrypted_private_key: string | null;
  push_uuid: string | null;
  push_token: string | null;
  banned: Flag;
  banned_at: string | null;
  device_note: string | null;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuthRequestsTable {
  id: string;
  user_id: string;
  organization_id: string | null;
  type: number;
  request_device_identifier: string;
  request_device_type: number;
  request_ip_address: string | null;
  request_country_name: string | null;
  response_device_identifier: string | null;
  access_code: string;
  public_key: string;
  key: string | null;
  master_password_hash: string | null;
  approved: number | null;
  creation_date: string;
  response_date: string | null;
  authentication_date: string | null;
}

export interface TrustedTwoFactorDeviceTokensTable {
  token: string;
  user_id: string;
  device_identifier: string;
  expires_at: number;
}

export interface TotpLoginReplaysTable {
  user_id: string;
  time_counter: number;
  consumed_at: number;
}

export interface WebauthnCredentialsTable {
  id: string;
  user_id: string;
  purpose: ColumnType<string, string | undefined, string>;
  name: string;
  public_key: string;
  credential_id: string;
  counter: ColumnType<number, number | undefined, number>;
  type: string | null;
  aa_guid: string | null;
  transports: string | null;
  encrypted_user_key: string | null;
  encrypted_public_key: string | null;
  encrypted_private_key: string | null;
  supports_prf: Flag;
  created_at: string;
  updated_at: string;
}

export interface WebauthnChallengesTable {
  challenge_hash: string;
  scope: string;
  user_id: string | null;
  expires_at: number;
  used_at: number | null;
  created_at: number;
}

export interface LoginAttemptsIpTable {
  ip: string;
  attempts: number;
  locked_until: number | null;
  updated_at: number;
}

export interface RateLimitBucketsTable {
  bucket_key: string;
  count: number;
  expires_at: number;
  updated_at: number;
}

export interface UsedAttachmentDownloadTokensTable {
  jti: string;
  expires_at: number;
}

export interface Database {
  config: ConfigTable;
  users: UsersTable;
  domain_settings: DomainSettingsTable;
  user_revisions: UserRevisionsTable;
  organizations: OrganizationsTable;
  org_memberships: OrgMembershipsTable;
  collections: CollectionsTable;
  collection_members: CollectionMembersTable;
  ciphers: CiphersTable;
  cipher_collections: CipherCollectionsTable;
  cipher_user_state: CipherUserStateTable;
  folders: FoldersTable;
  attachments: AttachmentsTable;
  sends: SendsTable;
  refresh_tokens: RefreshTokensTable;
  invites: InvitesTable;
  audit_logs: AuditLogsTable;
  devices: DevicesTable;
  auth_requests: AuthRequestsTable;
  trusted_two_factor_device_tokens: TrustedTwoFactorDeviceTokensTable;
  totp_login_replays: TotpLoginReplaysTable;
  webauthn_credentials: WebauthnCredentialsTable;
  webauthn_challenges: WebauthnChallengesTable;
  login_attempts_ip: LoginAttemptsIpTable;
  rate_limit_buckets: RateLimitBucketsTable;
  used_attachment_download_tokens: UsedAttachmentDownloadTokensTable;
}

export type Row<T extends keyof Database> = Selectable<Database[T]>;
export type NewRow<T extends keyof Database> = Insertable<Database[T]>;
export type RowUpdate<T extends keyof Database> = Updateable<Database[T]>;
