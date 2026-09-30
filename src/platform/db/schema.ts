import type { ColumnType, Generated, Insertable, Selectable, Updateable } from 'kysely';
import type { Sealed } from '../crypto';

// The tables as migrations/ creates them. Timestamps read and write as ISO
// strings (see createPool), JSON columns are written as JSON text.

type Timestamp = ColumnType<string, string, string>;
type Json<T> = ColumnType<T, string, string>;

export interface SettingsTable {
  key: string;
  value: Json<unknown>;
}

export interface JobLeasesTable {
  name: string;
  token: string;
  expires_at: Timestamp;
}

export interface UsersTable {
  id: string;
  email: string;
  name: string | null;
  master_password_hash: string;
  master_password_hint: string | null;
  key: string;
  key_id: string | null;
  public_key: string | null;
  private_key: string | null;
  kdf_type: number;
  kdf_iterations: number;
  kdf_memory: number | null;
  kdf_parallelism: number | null;
  security_stamp: string;
  role: Generated<'admin' | 'user'>;
  status: Generated<'active' | 'banned'>;
  verify_devices: Generated<boolean>;
  api_key: Sealed | null;
  recovery_code: Sealed | null;
  custom_domains: ColumnType<unknown[], string | undefined, string>;
  excluded_global_domains: ColumnType<number[], number[] | undefined, number[]>;
  revision_date: Timestamp;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface TwoFactorProvidersTable {
  user_id: string;
  type: number;
  data: Json<Record<string, unknown>>;
}

export interface TwoFactorRememberTokensTable {
  token_hash: Buffer;
  user_id: string;
  device_identifier: string;
  security_stamp: string;
  expires_at: Timestamp;
}

export interface DevicesTable {
  id: Generated<string>;
  user_id: string;
  identifier: string;
  name: string;
  type: number;
  note: string | null;
  session_stamp: string;
  push_uuid: string;
  push_token: string | null;
  encrypted_user_key: string | null;
  encrypted_public_key: string | null;
  encrypted_private_key: string | null;
  last_seen_at: Timestamp | null;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface RefreshTokensTable {
  token_hash: Buffer;
  family_id: string;
  user_id: string;
  device_id: string | null;
  device_session_stamp: string | null;
  security_stamp: string;
  client_type: string;
  created_at: Timestamp;
  last_used_at: Timestamp;
  expires_at: Timestamp;
  absolute_expires_at: Timestamp;
  rotated_at: Timestamp | null;
}

export interface WebauthnCredentialsTable {
  id: string;
  user_id: string;
  purpose: 'login' | 'twoFactor';
  slot: number | null;
  name: string;
  credential_id: string;
  public_key: string;
  counter: Generated<number>;
  type: string | null;
  aa_guid: string | null;
  transports: string[] | null;
  supports_prf: Generated<boolean>;
  encrypted_user_key: string | null;
  encrypted_public_key: string | null;
  encrypted_private_key: string | null;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface WebauthnChallengesTable {
  challenge_hash: Buffer;
  scope: string;
  user_id: string | null;
  expires_at: Timestamp;
  used_at: Timestamp | null;
}

export interface ConsumedTokensTable {
  key: string;
  expires_at: Timestamp;
}

export interface RateLimitsTable {
  key: string;
  count: number;
  expires_at: Timestamp;
}

export interface LoginFailuresTable {
  key: string;
  failures: number;
  locked_until: Timestamp | null;
  updated_at: Timestamp;
}

export interface FoldersTable {
  id: string;
  user_id: string;
  name: string;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface OrganizationsTable {
  id: string;
  name: string;
  billing_email: string;
  public_key: string | null;
  private_key: string | null;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface MembershipsTable {
  id: string;
  organization_id: string;
  user_id: string;
  status: number;
  type: number;
  access_all: Generated<boolean>;
  key: string | null;
  revoked_status: number | null;
  invited_by: string | null;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface CollectionsTable {
  id: string;
  organization_id: string;
  name: string;
  external_id: string | null;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface CollectionGrantsTable {
  collection_id: string;
  membership_id: string;
  read_only: Generated<boolean>;
  hide_passwords: Generated<boolean>;
  manage: Generated<boolean>;
}

export interface CiphersTable {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  type: number;
  key: string | null;
  reprompt: Generated<number>;
  data: Json<Record<string, unknown>>;
  created_at: Timestamp;
  updated_at: Timestamp;
  deleted_at: Timestamp | null;
}

export interface CipherCollectionsTable {
  cipher_id: string;
  collection_id: string;
}

export interface CipherUserStateTable {
  cipher_id: string;
  user_id: string;
  folder_id: string | null;
  favorite: Generated<boolean>;
  archived_at: Timestamp | null;
}

export interface AttachmentsTable {
  id: string;
  cipher_id: string;
  file_name: string;
  key: string | null;
  size: number;
  uploaded_at: Timestamp | null;
  created_at: Timestamp;
}

export interface SendsTable {
  id: string;
  user_id: string;
  type: number;
  key: string;
  data: Json<Record<string, unknown>>;
  password_hash: string | null;
  password_salt: string | null;
  password_iterations: number | null;
  max_access_count: number | null;
  access_count: Generated<number>;
  disabled: Generated<boolean>;
  hide_email: Generated<boolean>;
  created_at: Timestamp;
  updated_at: Timestamp;
  expiration_date: Timestamp | null;
  deletion_date: Timestamp;
}

export interface AuthRequestsTable {
  id: string;
  user_id: string;
  type: number;
  request_device_identifier: string;
  request_device_type: number;
  request_ip_address: string | null;
  request_country_name: string | null;
  response_device_identifier: string | null;
  access_code: string;
  public_key: string;
  key: string | null;
  approved: boolean | null;
  created_at: Timestamp;
  responded_at: Timestamp | null;
  authenticated_at: Timestamp | null;
}

export interface InvitesTable {
  code: string;
  created_by: string;
  used_by: string | null;
  status: 'active' | 'used';
  expires_at: Timestamp;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface AuditLogsTable {
  id: string;
  actor_user_id: string | null;
  action: string;
  category: string;
  level: string;
  target_type: string | null;
  target_id: string | null;
  metadata: Json<Record<string, unknown>> | null;
  created_at: Timestamp;
}

export interface Database {
  settings: SettingsTable;
  job_leases: JobLeasesTable;
  users: UsersTable;
  two_factor_providers: TwoFactorProvidersTable;
  two_factor_remember_tokens: TwoFactorRememberTokensTable;
  devices: DevicesTable;
  refresh_tokens: RefreshTokensTable;
  webauthn_credentials: WebauthnCredentialsTable;
  webauthn_challenges: WebauthnChallengesTable;
  consumed_tokens: ConsumedTokensTable;
  rate_limits: RateLimitsTable;
  login_failures: LoginFailuresTable;
  folders: FoldersTable;
  organizations: OrganizationsTable;
  memberships: MembershipsTable;
  collections: CollectionsTable;
  collection_grants: CollectionGrantsTable;
  ciphers: CiphersTable;
  cipher_collections: CipherCollectionsTable;
  cipher_user_state: CipherUserStateTable;
  attachments: AttachmentsTable;
  sends: SendsTable;
  auth_requests: AuthRequestsTable;
  invites: InvitesTable;
  audit_logs: AuditLogsTable;
}

export type Row<T extends keyof Database> = Selectable<Database[T]>;
export type NewRow<T extends keyof Database> = Insertable<Database[T]>;
export type RowUpdate<T extends keyof Database> = Updateable<Database[T]>;
