import type { Env, User } from '../types';
import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import {
  type UserOrgContext,
  canManageCollection,
  hasFullOrgAccess,
  isOrgAdminType,
  loadUserOrgContext,
  loadVisibleCollections,
} from '../services/org-access';
import {
  type Collection,
  type CollectionGrant,
  type OrgMembership,
  type Organization,
  ORG_MEMBER_STATUS,
  ORG_MEMBER_TYPE,
  countOwners,
  deleteCollectionStatement,
  deleteMembership,
  deleteOrganization,
  getCollection,
  getMembership,
  getMembershipByOrgAndUser,
  getOrganization,
  getOrganizationsByIds,
  insertGrantStatement,
  listCollectionsByOrg,
  listGrantsByOrg,
  listMembershipsByOrg,
  listMembershipsByUser,
  replaceCollectionGrantsStatements,
  replaceMembershipGrantsStatements,
  saveCollectionStatement,
  saveMembershipStatement,
  saveOrganizationStatement,
  touchOrgMembersRevision,
} from '../services/storage-org-repo';
import {
  collectionDetailsJson,
  collectionJson,
  grantJson,
  listJson,
  memberDetailsJson,
  memberMiniJson,
  organizationJson,
} from '../services/org-json';
import { notifyOrgMembersSync } from '../services/org-notifications';
import { notifyUserVaultSync } from '../services/notifications';
import { deleteAllAttachmentsForCiphers } from './attachments';

// Organization management API (Bitwarden-compatible subset).
//
// Differences from the official server / Vaultwarden, by design:
// - No email: invitations are only possible for registered users. The invitee
//   accepts in the web vault (GET /api/organizations/invitations), then an
//   admin confirms them, which hands over the org key wrapped for their public key.
// - No groups, policies, SSO, events, billing, API keys or account recovery.

type GuardLevel = 'member' | 'confirmed' | 'manager' | 'admin' | 'owner';

interface OrgGuard {
  org: Organization;
  membership: OrgMembership;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function normalizeId(value: unknown): string {
  return String(value ?? '').trim().toLowerCase();
}

async function readJson<T = any>(request: Request): Promise<T | Response> {
  try {
    const text = await request.text();
    return (text ? JSON.parse(text) : {}) as T;
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
}

function emptyOk(): Response {
  return new Response(null, { status: 200 });
}

async function requireOrg(env: Env, userId: string, orgId: string, level: GuardLevel): Promise<OrgGuard | Response> {
  if (!UUID_RE.test(orgId)) return errorResponse('Organization not found', 404);
  const [org, membership] = await Promise.all([
    getOrganization(env.DB, orgId),
    getMembershipByOrgAndUser(env.DB, orgId, userId),
  ]);
  // Same response for "no such org" and "not a member" to avoid probing.
  if (!org || !membership || membership.status === ORG_MEMBER_STATUS.REVOKED) {
    return errorResponse('Organization not found', 404);
  }
  if (level === 'member') return { org, membership };
  if (membership.status !== ORG_MEMBER_STATUS.CONFIRMED) {
    return errorResponse('You are not a confirmed member of this organization', 403);
  }
  const type = membership.type;
  const allowed =
    level === 'confirmed' ||
    (level === 'manager' && (isOrgAdminType(type) || type === ORG_MEMBER_TYPE.MANAGER)) ||
    (level === 'admin' && isOrgAdminType(type)) ||
    (level === 'owner' && type === ORG_MEMBER_TYPE.OWNER);
  if (!allowed) return errorResponse('You do not have permission to do this', 403);
  return { org, membership };
}

async function verifyMasterPassword(env: Env, user: User, body: any): Promise<Response | null> {
  const hash = String(body?.masterPasswordHash || body?.MasterPasswordHash || '').trim();
  if (!hash) return errorResponse('Master password is required', 400);
  const auth = new AuthService(env);
  const valid = await auth.verifyPassword(hash, user.masterPasswordHash, user.email);
  return valid ? null : errorResponse('Invalid password', 400);
}

// Accepts 0-4 or "Owner"/"Admin"/"User"/"Manager"/"Custom"; Custom is stored as Manager.
function parseMemberType(value: unknown): number | null {
  const raw = String(value ?? '').trim().toLowerCase();
  switch (raw) {
    case '0':
    case 'owner':
      return ORG_MEMBER_TYPE.OWNER;
    case '1':
    case 'admin':
      return ORG_MEMBER_TYPE.ADMIN;
    case '2':
    case 'user':
      return ORG_MEMBER_TYPE.USER;
    case '3':
    case 'manager':
    case '4':
    case 'custom':
      return ORG_MEMBER_TYPE.MANAGER;
    default:
      return null;
  }
}

function deriveAccessAll(rawType: unknown, type: number, permissions: any): boolean {
  if (isOrgAdminType(type)) return true;
  const isCustom = ['4', 'custom'].includes(String(rawType ?? '').trim().toLowerCase());
  return (
    isCustom &&
    permissions?.editAnyCollection === true &&
    permissions?.deleteAnyCollection === true &&
    permissions?.createNewCollections === true
  );
}

interface GrantInput {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

function parseGrantInputs(value: unknown): GrantInput[] {
  if (!Array.isArray(value)) return [];
  const out = new Map<string, GrantInput>();
  for (const item of value) {
    const id = normalizeId((item as any)?.id ?? (item as any)?.Id);
    if (!id) continue;
    out.set(id, {
      id,
      readOnly: !!((item as any)?.readOnly ?? (item as any)?.ReadOnly),
      hidePasswords: !!((item as any)?.hidePasswords ?? (item as any)?.HidePasswords),
      manage: !!((item as any)?.manage ?? (item as any)?.Manage),
    });
  }
  return Array.from(out.values());
}

function parseIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return Array.from(new Set(value.map(normalizeId).filter(Boolean)));
}

async function bumpOrg(env: Env, orgId: string): Promise<string> {
  const revisionDate = new Date().toISOString();
  await touchOrgMembersRevision(env.DB, orgId, revisionDate);
  notifyOrgMembersSync(env, orgId, revisionDate);
  return revisionDate;
}

async function bumpUser(env: Env, userId: string): Promise<void> {
  const storage = new StorageService(env.DB);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, null);
}

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

// POST /api/organizations
export async function handleCreateOrganization(request: Request, env: Env, user: User): Promise<Response> {
  const body = await readJson(request);
  if (body instanceof Response) return body;

  const name = String(body.name ?? '').trim();
  const billingEmail = String(body.billingEmail ?? user.email).trim().toLowerCase();
  const key = String(body.key ?? '').trim();
  const collectionName = String(body.collectionName ?? '').trim();
  const publicKey = String(body.keys?.publicKey ?? '').trim() || null;
  const privateKey = String(body.keys?.encryptedPrivateKey ?? '').trim() || null;

  if (!name || name.length > 200) return errorResponse('Organization name is required (max 200 characters)', 400);
  if (!key) return errorResponse('Organization key is required', 400);
  if (!/^[^\s@]+@[^\s@]+$/.test(billingEmail)) return errorResponse('BillingEmail is not a valid email address', 400);

  const now = new Date().toISOString();
  const org: Organization = {
    id: generateUUID(),
    name,
    billingEmail,
    publicKey,
    privateKey,
    createdAt: now,
    updatedAt: now,
  };
  const membership: OrgMembership = {
    id: generateUUID(),
    orgId: org.id,
    userId: user.id,
    status: ORG_MEMBER_STATUS.CONFIRMED,
    type: ORG_MEMBER_TYPE.OWNER,
    accessAll: true,
    akey: key,
    revokedStatus: null,
    invitedBy: null,
    createdAt: now,
    updatedAt: now,
  };
  const statements = [saveOrganizationStatement(env.DB, org), saveMembershipStatement(env.DB, membership)];
  if (collectionName) {
    statements.push(
      saveCollectionStatement(env.DB, {
        id: generateUUID(),
        orgId: org.id,
        name: collectionName,
        externalId: null,
        createdAt: now,
        updatedAt: now,
      })
    );
  }
  await env.DB.batch(statements);
  await bumpUser(env, user.id);
  return jsonResponse(organizationJson(org));
}

// GET /api/organizations/{id}
export async function handleGetOrganization(env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'owner');
  if (guard instanceof Response) return guard;
  return jsonResponse(organizationJson(guard.org));
}

// PUT/POST /api/organizations/{id}
export async function handleUpdateOrganization(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'owner');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;

  const name = body.name === undefined ? guard.org.name : String(body.name).trim();
  const billingEmail = body.billingEmail === undefined ? guard.org.billingEmail : String(body.billingEmail).trim().toLowerCase();
  if (!name || name.length > 200) return errorResponse('Organization name is required (max 200 characters)', 400);
  if (!/^[^\s@]+@[^\s@]+$/.test(billingEmail)) return errorResponse('BillingEmail is not a valid email address', 400);

  const org: Organization = { ...guard.org, name, billingEmail, updatedAt: new Date().toISOString() };
  await saveOrganizationStatement(env.DB, org).run();
  await bumpOrg(env, org.id);
  return jsonResponse(organizationJson(org));
}

// DELETE /api/organizations/{id}, POST /api/organizations/{id}/delete
export async function handleDeleteOrganization(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'owner');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const passwordError = await verifyMasterPassword(env, user, body);
  if (passwordError) return passwordError;

  await deleteOrganizationCompletely(env, orgId);
  return emptyOk();
}

// Removes the org with its ciphers' attachment blobs and bumps former members.
export async function deleteOrganizationCompletely(env: Env, orgId: string): Promise<void> {
  const memberUserIds = (await listMembershipsByOrg(env.DB, orgId)).map((member) => member.userId);
  const cipherRows = await env.DB
    .prepare('SELECT id FROM ciphers WHERE organization_id = ?')
    .bind(orgId)
    .all<{ id: string }>();
  const cipherIds = (cipherRows.results || []).map((row) => row.id);
  if (cipherIds.length) await deleteAllAttachmentsForCiphers(env, cipherIds);
  await deleteOrganization(env.DB, orgId);
  for (const userId of memberUserIds) await bumpUser(env, userId);
}

// POST /api/organizations/{id}/leave  (also declines a pending invitation)
export async function handleLeaveOrganization(env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'member');
  if (guard instanceof Response) return guard;
  const { membership } = guard;
  if (
    membership.type === ORG_MEMBER_TYPE.OWNER &&
    membership.status === ORG_MEMBER_STATUS.CONFIRMED &&
    (await countOwners(env.DB, orgId)) <= 1
  ) {
    return errorResponse("The last owner can't leave", 400);
  }
  await deleteMembership(env.DB, membership.id);
  await bumpUser(env, user.id);
  return emptyOk();
}

// GET /api/organizations/{id}/keys, /public-key
export async function handleGetOrganizationKeys(env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'member');
  if (guard instanceof Response) return guard;
  return jsonResponse({ object: 'organizationPublicKey', publicKey: guard.org.publicKey });
}

// POST /api/organizations/{id}/keys (older orgs created without a key pair)
export async function handleSetOrganizationKeys(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  if (guard.org.publicKey && guard.org.privateKey) return errorResponse('Organization Keys already exist', 400);
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const publicKey = String(body.publicKey ?? '').trim();
  const privateKey = String(body.encryptedPrivateKey ?? '').trim();
  if (!publicKey || !privateKey) return errorResponse('publicKey and encryptedPrivateKey are required', 400);
  const org = { ...guard.org, publicKey, privateKey, updatedAt: new Date().toISOString() };
  await saveOrganizationStatement(env.DB, org).run();
  await bumpOrg(env, orgId);
  return jsonResponse({ object: 'organizationKeys', publicKey, privateKey });
}

// GET /api/users/{userId}/public-key
export async function handleGetUserPublicKey(env: Env, targetUserId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const target = await storage.getUserById(normalizeId(targetUserId));
  if (!target?.publicKey) return errorResponse('User not found', 404);
  return jsonResponse({ userId: target.id, publicKey: target.publicKey, object: 'userKey' });
}

// GET /api/organizations/invitations (MoliWarden extension for the web vault)
export async function handleListMyInvitations(env: Env, user: User): Promise<Response> {
  const pending = (await listMembershipsByUser(env.DB, user.id)).filter(
    (membership) => membership.status === ORG_MEMBER_STATUS.INVITED || membership.status === ORG_MEMBER_STATUS.ACCEPTED
  );
  const orgs = new Map((await getOrganizationsByIds(env.DB, pending.map((m) => m.orgId))).map((org) => [org.id, org]));
  const storage = new StorageService(env.DB);
  const data = [];
  for (const membership of pending) {
    const org = orgs.get(membership.orgId);
    if (!org) continue;
    const inviter = membership.invitedBy ? await storage.getUserById(membership.invitedBy) : null;
    data.push({
      id: membership.id,
      organizationId: org.id,
      organizationName: org.name,
      status: membership.status,
      type: membership.type,
      invitedByEmail: inviter?.email ?? null,
      object: 'organizationInvitation',
    });
  }
  return jsonResponse(listJson(data));
}

// POST /api/organizations/{id}/users/{memberId}/accept
export async function handleAcceptInvitation(env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const membership = await getMembership(env.DB, normalizeId(memberId));
  if (!membership || membership.orgId !== normalizeId(orgId) || membership.userId !== user.id) {
    return errorResponse('Invitation not found', 404);
  }
  if (membership.status !== ORG_MEMBER_STATUS.INVITED) {
    return errorResponse('Invitation already accepted', 400);
  }
  await saveMembershipStatement(env.DB, {
    ...membership,
    status: ORG_MEMBER_STATUS.ACCEPTED,
    updatedAt: new Date().toISOString(),
  }).run();
  await bumpOrg(env, membership.orgId);
  return emptyOk();
}

// GET /api/organizations/{id}/policies  (policies are not supported)
export function handleListPolicies(): Response {
  return jsonResponse(listJson([]));
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

async function loadMembersWithGrants(env: Env, orgId: string) {
  const [members, grants] = await Promise.all([listMembershipsByOrg(env.DB, orgId), listGrantsByOrg(env.DB, orgId)]);
  const grantsByMember = new Map<string, CollectionGrant[]>();
  for (const grant of grants) {
    const list = grantsByMember.get(grant.membershipId) || [];
    list.push(grant);
    grantsByMember.set(grant.membershipId, list);
  }
  return { members, grantsByMember };
}

// GET /api/organizations/{id}/users
export async function handleListMembers(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  if (!hasFullOrgAccess(guard.membership)) return errorResponse('Resource not found.', 404);
  const includeCollections = new URL(request.url).searchParams.get('includeCollections') === 'true';
  const { members, grantsByMember } = await loadMembersWithGrants(env, orgId);
  return jsonResponse(listJson(members.map((member) => memberDetailsJson(member, grantsByMember.get(member.id) || [], includeCollections))));
}

// GET /api/organizations/{id}/users/mini-details
export async function handleListMembersMini(env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  const members = await listMembershipsByOrg(env.DB, orgId);
  return jsonResponse(listJson(members.map(memberMiniJson)));
}

// GET /api/organizations/{id}/users/{memberId}
export async function handleGetMember(env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const { members, grantsByMember } = await loadMembersWithGrants(env, orgId);
  const member = members.find((item) => item.id === normalizeId(memberId));
  if (!member) return errorResponse('Member not found', 404);
  return jsonResponse(memberDetailsJson(member, grantsByMember.get(member.id) || [], true));
}

async function validateCollectionIds(env: Env, orgId: string, grants: GrantInput[]): Promise<string | null> {
  if (!grants.length) return null;
  const orgCollections = new Set((await listCollectionsByOrg(env.DB, orgId)).map((collection) => collection.id));
  for (const grant of grants) {
    if (!orgCollections.has(grant.id)) return 'Collection not found in Organization';
  }
  return null;
}

// POST /api/organizations/{id}/users/invite
export async function handleInviteMembers(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;

  const emails = Array.isArray(body.emails)
    ? Array.from(new Set(body.emails.map((email: unknown) => String(email ?? '').trim().toLowerCase()).filter(Boolean))) as string[]
    : [];
  if (!emails.length) return errorResponse('At least one email is required', 400);
  if (emails.length > 20) return errorResponse('You can invite at most 20 users at once', 400);
  const type = parseMemberType(body.type);
  if (type === null) return errorResponse('Invalid type', 400);
  if (type !== ORG_MEMBER_TYPE.USER && guard.membership.type !== ORG_MEMBER_TYPE.OWNER) {
    return errorResponse('Only Owners can invite Managers, Admins or Owners', 403);
  }
  const accessAll = deriveAccessAll(body.type, type, body.permissions);
  const grants = accessAll ? [] : parseGrantInputs(body.collections);
  const collectionError = await validateCollectionIds(env, orgId, grants);
  if (collectionError) return errorResponse(collectionError, 400);

  const storage = new StorageService(env.DB);
  const targets: User[] = [];
  for (const email of emails) {
    const target = await storage.getUser(email);
    if (!target || target.status !== 'active') return errorResponse(`User does not exist: ${email}`, 400);
    if (await getMembershipByOrgAndUser(env.DB, orgId, target.id)) {
      return errorResponse(`User already in organization: ${email}`, 400);
    }
    targets.push(target);
  }

  const now = new Date().toISOString();
  const statements: D1PreparedStatement[] = [];
  for (const target of targets) {
    const membership: OrgMembership = {
      id: generateUUID(),
      orgId,
      userId: target.id,
      status: ORG_MEMBER_STATUS.INVITED,
      type,
      accessAll,
      akey: null,
      revokedStatus: null,
      invitedBy: user.id,
      createdAt: now,
      updatedAt: now,
    };
    statements.push(saveMembershipStatement(env.DB, membership));
    for (const grant of grants) {
      statements.push(insertGrantStatement(env.DB, { ...grant, collectionId: grant.id, membershipId: membership.id }));
    }
  }
  await env.DB.batch(statements);
  for (const target of targets) await bumpUser(env, target.id);
  return emptyOk();
}

// POST /api/organizations/{id}/users/{memberId}/reinvite
export async function handleReinviteMember(env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const member = await getMembership(env.DB, normalizeId(memberId));
  if (!member || member.orgId !== orgId) return errorResponse('Member not found', 404);
  if (member.status !== ORG_MEMBER_STATUS.INVITED) return errorResponse('The user already accepted or was already invited', 400);
  // No email delivery: the invitation stays visible in the invitee's web vault.
  return emptyOk();
}

async function confirmOne(env: Env, guard: OrgGuard, memberId: string, key: string): Promise<string | null> {
  if (!key) return 'Invalid key provided';
  const member = await getMembership(env.DB, normalizeId(memberId));
  if (!member || member.orgId !== guard.org.id) return 'Member not found';
  if (member.type !== ORG_MEMBER_TYPE.USER && guard.membership.type !== ORG_MEMBER_TYPE.OWNER) {
    return 'Only Owners can confirm Managers, Admins or Owners';
  }
  if (member.status !== ORG_MEMBER_STATUS.ACCEPTED) return 'User in invalid state';
  await saveMembershipStatement(env.DB, {
    ...member,
    status: ORG_MEMBER_STATUS.CONFIRMED,
    akey: key,
    updatedAt: new Date().toISOString(),
  }).run();
  await bumpUser(env, member.userId);
  return null;
}

// POST /api/organizations/{id}/users/{memberId}/confirm
export async function handleConfirmMember(request: Request, env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const error = await confirmOne(env, guard, memberId, String(body.key ?? '').trim());
  if (error) return errorResponse(error, 400);
  await bumpOrg(env, orgId);
  return emptyOk();
}

// POST /api/organizations/{id}/users/confirm
export async function handleBulkConfirmMembers(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const entries = Array.isArray(body.keys) ? body.keys : [];
  const data = [];
  for (const entry of entries) {
    const id = normalizeId(entry?.id);
    const error = await confirmOne(env, guard, id, String(entry?.key ?? '').trim());
    data.push({ object: 'OrganizationBulkConfirmResponseModel', id, error: error || '' });
  }
  await bumpOrg(env, orgId);
  return jsonResponse(listJson(data));
}

// POST /api/organizations/{id}/users/public-keys
export async function handleMembersPublicKeys(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const ids = new Set(parseIds(body.ids));
  const members = await listMembershipsByOrg(env.DB, orgId);
  const data = members
    .filter((member) => ids.has(member.id))
    .map((member) => ({ object: 'organizationUserPublicKeyResponseModel', id: member.id, userId: member.userId, key: member.publicKey }));
  return jsonResponse(listJson(data));
}

// PUT/POST /api/organizations/{id}/users/{memberId}
export async function handleEditMember(request: Request, env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const member = await getMembership(env.DB, normalizeId(memberId));
  if (!member || member.orgId !== orgId) return errorResponse('Member not found', 404);

  const type = parseMemberType(body.type ?? member.type);
  if (type === null) return errorResponse('Invalid type', 400);
  const callerIsOwner = guard.membership.type === ORG_MEMBER_TYPE.OWNER;
  if (type !== member.type && (isOrgAdminType(type) || isOrgAdminType(member.type)) && !callerIsOwner) {
    return errorResponse('Only Owners can grant and remove Admin or Owner privileges', 403);
  }
  if (member.type === ORG_MEMBER_TYPE.OWNER && !callerIsOwner) {
    return errorResponse('Only Owners can edit Owner users', 403);
  }
  if (
    member.type === ORG_MEMBER_TYPE.OWNER &&
    type !== ORG_MEMBER_TYPE.OWNER &&
    member.status === ORG_MEMBER_STATUS.CONFIRMED &&
    (await countOwners(env.DB, orgId)) <= 1
  ) {
    return errorResponse("Can't delete the last owner", 400);
  }

  const accessAll = deriveAccessAll(body.type ?? member.type, type, body.permissions);
  const grants = accessAll ? [] : parseGrantInputs(body.collections);
  const collectionError = await validateCollectionIds(env, orgId, grants);
  if (collectionError) return errorResponse(collectionError, 400);

  await env.DB.batch([
    saveMembershipStatement(env.DB, { ...member, type, accessAll, updatedAt: new Date().toISOString() }),
    ...replaceMembershipGrantsStatements(
      env.DB,
      member.id,
      grants.map((grant) => ({ collectionId: grant.id, readOnly: grant.readOnly, hidePasswords: grant.hidePasswords, manage: grant.manage }))
    ),
  ]);
  await bumpUser(env, member.userId);
  return emptyOk();
}

async function removeOne(env: Env, guard: OrgGuard, memberId: string): Promise<string | null> {
  const member = await getMembership(env.DB, normalizeId(memberId));
  if (!member || member.orgId !== guard.org.id) return 'Member not found';
  if (member.type !== ORG_MEMBER_TYPE.USER && guard.membership.type !== ORG_MEMBER_TYPE.OWNER) {
    return 'Only Owners can delete Admins or Owners';
  }
  if (
    member.type === ORG_MEMBER_TYPE.OWNER &&
    member.status === ORG_MEMBER_STATUS.CONFIRMED &&
    (await countOwners(env.DB, guard.org.id)) <= 1
  ) {
    return "Can't delete the last owner";
  }
  await deleteMembership(env.DB, member.id);
  await bumpUser(env, member.userId);
  return null;
}

// DELETE /api/organizations/{id}/users/{memberId}
export async function handleRemoveMember(env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const error = await removeOne(env, guard, memberId);
  if (error) return errorResponse(error, error === 'Member not found' ? 404 : 400);
  await bumpOrg(env, orgId);
  return emptyOk();
}

// DELETE /api/organizations/{id}/users  { ids }
export async function handleBulkRemoveMembers(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const data = [];
  for (const id of parseIds(body.ids)) {
    const error = await removeOne(env, guard, id);
    data.push({ object: 'OrganizationBulkConfirmResponseModel', id, error: error || '' });
  }
  await bumpOrg(env, orgId);
  return jsonResponse(listJson(data));
}

async function setRevoked(env: Env, guard: OrgGuard, memberId: string, revoke: boolean): Promise<string | null> {
  const member = await getMembership(env.DB, normalizeId(memberId));
  if (!member || member.orgId !== guard.org.id) return 'Member not found';
  if (member.userId === guard.membership.userId) {
    return revoke ? 'You cannot revoke yourself' : 'You cannot restore yourself';
  }
  if (member.type === ORG_MEMBER_TYPE.OWNER && guard.membership.type !== ORG_MEMBER_TYPE.OWNER) {
    return 'Only owners can revoke or restore other owners';
  }
  const now = new Date().toISOString();
  if (revoke) {
    if (member.status === ORG_MEMBER_STATUS.REVOKED) return 'Already revoked';
    if (member.type === ORG_MEMBER_TYPE.OWNER && (await countOwners(env.DB, guard.org.id)) <= 1) {
      return 'Organization must have at least one confirmed owner';
    }
    await saveMembershipStatement(env.DB, {
      ...member,
      status: ORG_MEMBER_STATUS.REVOKED,
      revokedStatus: member.status,
      updatedAt: now,
    }).run();
  } else {
    if (member.status !== ORG_MEMBER_STATUS.REVOKED) return 'User is already active';
    await saveMembershipStatement(env.DB, {
      ...member,
      status: member.revokedStatus ?? ORG_MEMBER_STATUS.ACCEPTED,
      revokedStatus: null,
      updatedAt: now,
    }).run();
  }
  await bumpUser(env, member.userId);
  return null;
}

// PUT /api/organizations/{id}/users/{memberId}/revoke | /restore
export async function handleRevokeMember(env: Env, user: User, orgId: string, memberId: string, revoke: boolean): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const error = await setRevoked(env, guard, memberId, revoke);
  if (error) return errorResponse(error, error === 'Member not found' ? 404 : 400);
  await bumpOrg(env, orgId);
  return emptyOk();
}

// PUT /api/organizations/{id}/users/revoke | /restore  { ids }
export async function handleBulkRevokeMembers(request: Request, env: Env, user: User, orgId: string, revoke: boolean): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'admin');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const data = [];
  for (const id of parseIds(body.ids)) {
    const error = await setRevoked(env, guard, id, revoke);
    data.push({ object: 'OrganizationUserBulkResponseModel', id, error: error || '' });
  }
  await bumpOrg(env, orgId);
  return jsonResponse(listJson(data));
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

// GET /api/collections  (collections visible to the caller across orgs)
export async function handleListMyCollections(env: Env, user: User): Promise<Response> {
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const collections = await loadVisibleCollections(env.DB, ctx);
  return jsonResponse(listJson(collections.map(collectionJson)));
}

// GET /api/organizations/{id}/collections
export async function handleListOrgCollections(env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  if (!hasFullOrgAccess(guard.membership)) return errorResponse('Resource not found.', 404);
  const collections = await listCollectionsByOrg(env.DB, orgId);
  return jsonResponse(listJson(collections.map(collectionJson)));
}

function collectionAccessDetails(
  collection: Collection,
  ctx: UserOrgContext,
  members: Awaited<ReturnType<typeof listMembershipsByOrg>>,
  grants: CollectionGrant[],
  assigned: boolean,
  includeManageAll: boolean
): Record<string, unknown> {
  const typeByMember = new Map(members.map((member) => [member.id, member.type]));
  const users = grants
    .filter((grant) => grant.collectionId === collection.id)
    .map((grant) => grantJson(grant, typeByMember.get(grant.membershipId) ?? ORG_MEMBER_TYPE.USER, 'member'));
  if (includeManageAll) {
    const listed = new Set(users.map((entry) => entry.id));
    for (const member of members) {
      if (listed.has(member.id)) continue;
      if (member.status === ORG_MEMBER_STATUS.CONFIRMED && member.accessAll && member.type !== ORG_MEMBER_TYPE.USER) {
        users.push({ id: member.id, readOnly: false, hidePasswords: false, manage: true });
      }
    }
  }
  return {
    ...collectionDetailsJson(collection, ctx),
    assigned,
    users,
    groups: [],
    unmanaged: false,
    object: 'collectionAccessDetails',
  };
}

// GET /api/organizations/{id}/collections/details
export async function handleListOrgCollectionDetails(env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const [collections, members, grants] = await Promise.all([
    listCollectionsByOrg(env.DB, orgId),
    listMembershipsByOrg(env.DB, orgId),
    listGrantsByOrg(env.DB, orgId),
  ]);
  const full = hasFullOrgAccess(guard.membership);
  const data = collections
    .filter((collection) => full || ctx.grantsByCollection.has(collection.id))
    .map((collection) => {
      // Access lists are only shown for collections the caller may manage.
      const manageable = full || canManageCollection(ctx, orgId, collection.id);
      return collectionAccessDetails(collection, ctx, members, manageable ? grants : [], true, manageable);
    });
  return jsonResponse(listJson(data));
}

async function requireManageableCollection(
  env: Env,
  user: User,
  orgId: string,
  collectionId: string
): Promise<{ guard: OrgGuard; ctx: UserOrgContext; collection: Collection } | Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  const collection = await getCollection(env.DB, normalizeId(collectionId));
  if (!collection || collection.orgId !== orgId) return errorResponse('Collection not found', 404);
  const ctx = await loadUserOrgContext(env.DB, user.id);
  if (!canManageCollection(ctx, orgId, collection.id)) {
    return errorResponse("You don't have permission to manage this collection", 403);
  }
  return { guard, ctx, collection };
}

// GET /api/organizations/{id}/collections/{collectionId}/details
export async function handleGetCollectionDetails(env: Env, user: User, orgId: string, collectionId: string): Promise<Response> {
  const resolved = await requireManageableCollection(env, user, orgId, collectionId);
  if (resolved instanceof Response) return resolved;
  const [members, grants] = await Promise.all([listMembershipsByOrg(env.DB, orgId), listGrantsByOrg(env.DB, orgId)]);
  const assigned = hasFullOrgAccess(resolved.guard.membership) || resolved.ctx.grantsByCollection.has(resolved.collection.id);
  const details = collectionAccessDetails(resolved.collection, resolved.ctx, members, grants, assigned, false);
  delete details.unmanaged;
  return jsonResponse(details);
}

// GET /api/organizations/{id}/collections/{collectionId}/users
export async function handleGetCollectionUsers(env: Env, user: User, orgId: string, collectionId: string): Promise<Response> {
  const resolved = await requireManageableCollection(env, user, orgId, collectionId);
  if (resolved instanceof Response) return resolved;
  const grants = (await listGrantsByOrg(env.DB, orgId)).filter((grant) => grant.collectionId === resolved.collection.id);
  return jsonResponse(
    grants.map((grant) => ({ id: grant.membershipId, readOnly: grant.readOnly, hidePasswords: grant.hidePasswords, manage: grant.manage }))
  );
}

async function buildCollectionGrantStatements(
  env: Env,
  orgId: string,
  collectionId: string,
  usersInput: unknown
): Promise<D1PreparedStatement[] | string> {
  const inputs = parseGrantInputs(usersInput);
  const members = new Map((await listMembershipsByOrg(env.DB, orgId)).map((member) => [member.id, member]));
  const grants = [];
  for (const input of inputs) {
    const member = members.get(input.id);
    if (!member) return 'Invalid member';
    if (member.accessAll) continue; // access comes from access_all
    grants.push({ membershipId: member.id, readOnly: input.readOnly, hidePasswords: input.hidePasswords, manage: input.manage });
  }
  return replaceCollectionGrantsStatements(env.DB, collectionId, grants);
}

// POST /api/organizations/{id}/collections
export async function handleCreateCollection(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  if (guard.membership.type === ORG_MEMBER_TYPE.MANAGER && !guard.membership.accessAll) {
    return errorResponse("You don't have permission to create collections", 403);
  }
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const name = String(body.name ?? '').trim();
  if (!name) return errorResponse('Collection name is required', 400);

  const now = new Date().toISOString();
  const collection: Collection = {
    id: generateUUID(),
    orgId,
    name,
    externalId: String(body.externalId ?? '').trim() || null,
    createdAt: now,
    updatedAt: now,
  };
  const grantStatements = await buildCollectionGrantStatements(env, orgId, collection.id, body.users);
  if (typeof grantStatements === 'string') return errorResponse(grantStatements, 400);
  await env.DB.batch([saveCollectionStatement(env.DB, collection), ...grantStatements]);
  await bumpOrg(env, orgId);
  const ctx = await loadUserOrgContext(env.DB, user.id);
  return jsonResponse(collectionDetailsJson(collection, ctx));
}

// PUT/POST /api/organizations/{id}/collections/{collectionId}
export async function handleUpdateCollection(request: Request, env: Env, user: User, orgId: string, collectionId: string): Promise<Response> {
  const resolved = await requireManageableCollection(env, user, orgId, collectionId);
  if (resolved instanceof Response) return resolved;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const name = body.name === undefined ? resolved.collection.name : String(body.name).trim();
  if (!name) return errorResponse('Collection name is required', 400);

  const collection: Collection = {
    ...resolved.collection,
    name,
    externalId: body.externalId === undefined ? resolved.collection.externalId : String(body.externalId ?? '').trim() || null,
    updatedAt: new Date().toISOString(),
  };
  const statements: D1PreparedStatement[] = [saveCollectionStatement(env.DB, collection)];
  if (body.users !== undefined) {
    const grantStatements = await buildCollectionGrantStatements(env, orgId, collection.id, body.users);
    if (typeof grantStatements === 'string') return errorResponse(grantStatements, 400);
    statements.push(...grantStatements);
  }
  await env.DB.batch(statements);
  await bumpOrg(env, orgId);
  const ctx = await loadUserOrgContext(env.DB, user.id);
  return jsonResponse(collectionDetailsJson(collection, ctx));
}

// POST /api/organizations/{id}/collections/bulk-access
export async function handleCollectionsBulkAccess(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const statements: D1PreparedStatement[] = [];
  for (const collectionId of parseIds(body.collectionIds)) {
    const collection = await getCollection(env.DB, collectionId);
    if (!collection || collection.orgId !== orgId) return errorResponse('Collection not found', 404);
    if (!canManageCollection(ctx, orgId, collectionId)) {
      return errorResponse("You don't have permission to manage this collection", 403);
    }
    const grantStatements = await buildCollectionGrantStatements(env, orgId, collectionId, body.users);
    if (typeof grantStatements === 'string') return errorResponse(grantStatements, 400);
    statements.push(...grantStatements);
  }
  if (statements.length) await env.DB.batch(statements);
  await bumpOrg(env, orgId);
  return emptyOk();
}

// DELETE /api/organizations/{id}/collections/{collectionId}
export async function handleDeleteCollection(env: Env, user: User, orgId: string, collectionId: string): Promise<Response> {
  const resolved = await requireManageableCollection(env, user, orgId, collectionId);
  if (resolved instanceof Response) return resolved;
  // Ciphers stay in the organization; only their link to the collection goes.
  await deleteCollectionStatement(env.DB, orgId, resolved.collection.id).run();
  await bumpOrg(env, orgId);
  return emptyOk();
}

// DELETE /api/organizations/{id}/collections  { ids }
export async function handleBulkDeleteCollections(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const guard = await requireOrg(env, user.id, orgId, 'manager');
  if (guard instanceof Response) return guard;
  const body = await readJson(request);
  if (body instanceof Response) return body;
  const ctx = await loadUserOrgContext(env.DB, user.id);
  const ids = parseIds(body.ids);
  for (const id of ids) {
    const collection = await getCollection(env.DB, id);
    if (!collection || collection.orgId !== orgId) return errorResponse('Collection not found', 404);
    if (!canManageCollection(ctx, orgId, id)) return errorResponse("You don't have permission to manage this collection", 403);
  }
  if (ids.length) await env.DB.batch(ids.map((id) => deleteCollectionStatement(env.DB, orgId, id)));
  await bumpOrg(env, orgId);
  return emptyOk();
}


// Called before a user account is deleted. Organizations where the user is
// the only member are deleted with them; if the user is the last confirmed
// owner of an org that still has other members, deletion is refused so the
// org is not left without anyone able to administer it.
export async function prepareUserRemovalFromOrganizations(env: Env, userId: string): Promise<string | null> {
  const memberships = await listMembershipsByUser(env.DB, userId);
  const soleMemberOrgs: string[] = [];
  for (const membership of memberships) {
    const members = await listMembershipsByOrg(env.DB, membership.orgId);
    if (members.length === 1) {
      soleMemberOrgs.push(membership.orgId);
      continue;
    }
    if (
      membership.type === ORG_MEMBER_TYPE.OWNER &&
      membership.status === ORG_MEMBER_STATUS.CONFIRMED &&
      (await countOwners(env.DB, membership.orgId)) <= 1
    ) {
      const org = await getOrganization(env.DB, membership.orgId);
      return `User is the last owner of organization "${org?.name ?? membership.orgId}". Transfer ownership or delete the organization first.`;
    }
  }
  for (const orgId of soleMemberOrgs) await deleteOrganizationCompletely(env, orgId);
  return null;
}
