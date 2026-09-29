// Organization / membership / collection persistence.
//
// What the admin handlers still read; src/modules/organizations has the rest.

export const ORG_MEMBER_STATUS = {
  REVOKED: -1,
  INVITED: 0,
  ACCEPTED: 1,
  CONFIRMED: 2,
} as const;

export const ORG_MEMBER_TYPE = {
  OWNER: 0,
  ADMIN: 1,
  USER: 2,
  MANAGER: 3,
  // Bitwarden's "Custom" role; stored as MANAGER (see normalizeMemberType).
  CUSTOM: 4,
} as const;

export interface Organization {
  id: string;
  name: string;
  billingEmail: string;
  publicKey: string | null;
  privateKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface OrgMembership {
  id: string;
  orgId: string;
  userId: string;
  status: number;
  type: number;
  accessAll: boolean;
  akey: string | null;
  revokedStatus: number | null;
  invitedBy: string | null;
  createdAt: string;
  updatedAt: string;
}

interface OrgMembershipWithUser extends OrgMembership {
  email: string;
  name: string | null;
  publicKey: string | null;
  hasTwoFactor: boolean;
}

interface OrganizationRow {
  id: string;
  name: string;
  billing_email: string;
  public_key: string | null;
  private_key: string | null;
  created_at: string;
  updated_at: string;
}

interface MembershipRow {
  id: string;
  org_id: string;
  user_id: string;
  status: number;
  type: number;
  access_all: number;
  akey: string | null;
  revoked_status: number | null;
  invited_by: string | null;
  created_at: string;
  updated_at: string;
}

const MEMBERSHIP_COLUMNS =
  'm.id, m.org_id, m.user_id, m.status, m.type, m.access_all, m.akey, m.revoked_status, m.invited_by, m.created_at, m.updated_at';

function toOrganization(row: OrganizationRow): Organization {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email,
    publicKey: row.public_key,
    privateKey: row.private_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function toMembership(row: MembershipRow): OrgMembership {
  return {
    id: row.id,
    orgId: row.org_id,
    userId: row.user_id,
    status: Number(row.status),
    type: Number(row.type),
    accessAll: !!row.access_all,
    akey: row.akey,
    revokedStatus: row.revoked_status === null ? null : Number(row.revoked_status),
    invitedBy: row.invited_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// --- Organizations ---

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db
    .prepare('SELECT id, name, billing_email, public_key, private_key, created_at, updated_at FROM organizations WHERE id = ?')
    .bind(id)
    .first<OrganizationRow>();
  return row ? toOrganization(row) : null;
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  // ON DELETE CASCADE removes memberships, collections, grants and org ciphers
  // (and through ciphers: attachments rows, cipher_collections, cipher_user_state).
  await db.prepare('DELETE FROM organizations WHERE id = ?').bind(id).run();
}

// --- Memberships ---

export async function listMembershipsByUser(db: D1Database, userId: string): Promise<OrgMembership[]> {
  const res = await db
    .prepare(`SELECT ${MEMBERSHIP_COLUMNS} FROM org_memberships m WHERE m.user_id = ? ORDER BY m.created_at ASC`)
    .bind(userId)
    .all<MembershipRow>();
  return (res.results || []).map(toMembership);
}

export async function listMembershipsByOrg(db: D1Database, orgId: string): Promise<OrgMembershipWithUser[]> {
  const res = await db
    .prepare(
      `SELECT ${MEMBERSHIP_COLUMNS}, u.email, u.name, u.public_key AS user_public_key, ` +
      '(u.totp_secret IS NOT NULL OR u.yubikey_key1 IS NOT NULL OR EXISTS (' +
      "SELECT 1 FROM webauthn_credentials w WHERE w.user_id = u.id AND w.purpose <> 'login')) AS has_two_factor " +
      'FROM org_memberships m INNER JOIN users u ON u.id = m.user_id WHERE m.org_id = ? ORDER BY m.created_at ASC'
    )
    .bind(orgId)
    .all<MembershipRow & { email: string; name: string | null; user_public_key: string | null; has_two_factor: boolean }>();
  return (res.results || []).map((row) => ({
    ...toMembership(row),
    email: row.email,
    name: row.name,
    publicKey: row.user_public_key,
    hasTwoFactor: !!row.has_two_factor,
  }));
}

export async function countOwners(db: D1Database, orgId: string): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM org_memberships WHERE org_id = ? AND type = ? AND status = ?')
    .bind(orgId, ORG_MEMBER_TYPE.OWNER, ORG_MEMBER_STATUS.CONFIRMED)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}
