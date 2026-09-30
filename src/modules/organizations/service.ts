import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, forbidden, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { findUserById } from '../accounts/repo';
import { listAttachments } from '../attachments/repo';
import { removeAttachmentFiles } from '../attachments/files';
import { requireMasterPassword } from '../auth/password';
import { listCipherIds } from '../ciphers/repo';
import { PushType } from '../push/service';
import { commit } from '../sync/changes';
import { isAdminType } from './access';
import {
  countOwners,
  deleteMembership,
  deleteOrganization as deleteOrganizationRow,
  findMembership,
  findMembershipOf,
  findOrganization,
  insertCollections,
  listMembers,
  listOrganizations,
  listUserMemberships,
  MemberStatus,
  MemberType,
  saveMemberships,
  saveOrganization,
  type Membership,
  type Organization,
} from './repo';
import { organizationJson, profileOrganizationsJson } from './responses';
import type { CreateOrgInput } from './schemas';

// Organizations and the caller's own membership. Differences from
// Bitwarden, by design: there is no email, so only registered users are
// invited, and they accept in the web vault; there are no groups, policies,
// SSO, events, billing or account recovery.

export const now = () => new Date().toISOString();

// Everyone in the organization syncs.
export const orgChange = (orgId: string) => ({ orgIds: [orgId], push: { type: PushType.SyncVault } });
// These users sync.
export const usersChange = (...userIds: string[]) => ({ userIds, push: { type: PushType.SyncVault } });

export type Level = 'member' | 'confirmed' | 'manager' | 'admin' | 'owner';

export interface Guarded {
  org: Organization;
  membership: Membership;
}

const ALLOWED: Record<Exclude<Level, 'member'>, (type: number) => boolean> = {
  confirmed: () => true,
  manager: (type) => isAdminType(type) || type === MemberType.Manager,
  admin: isAdminType,
  owner: (type) => type === MemberType.Owner,
};

// The organization, if the user's membership reaches `level`. Organizations
// the user is not in do not exist for them.
export async function requireOrg(db: Executor, userId: string, orgId: string, level: Level): Promise<Guarded> {
  const [org, membership] = await Promise.all([findOrganization(db, orgId), findMembershipOf(db, orgId, userId)]);
  if (!org || !membership || membership.status === MemberStatus.Revoked) throw notFound('Organization not found');
  if (level === 'member') return { org, membership };
  if (membership.status !== MemberStatus.Confirmed) throw forbidden('You are not a confirmed member of this organization');
  if (!ALLOWED[level](membership.type)) throw forbidden('You do not have permission to do this');
  return { org, membership };
}

// Only owners of the organization give or take the rights of other owners
// and admins.
export function requireOwnerFor(guarded: Guarded, type: number, message: string): void {
  if (type !== MemberType.User && guarded.membership.type !== MemberType.Owner) throw forbidden(message);
}

export async function isLastOwner(db: Executor, member: Membership): Promise<boolean> {
  return (
    member.type === MemberType.Owner && member.status === MemberStatus.Confirmed && (await countOwners(db, member.orgId)) <= 1
  );
}

// The caller becomes its owner.
export async function createOrganization(deps: Deps, caller: Caller, input: CreateOrgInput) {
  const date = now();
  const org: Organization = {
    id: randomUUID(),
    name: input.name,
    billingEmail: input.billingEmail ?? caller.user.email.toLowerCase(),
    publicKey: input.keys.publicKey || null,
    privateKey: input.keys.encryptedPrivateKey || null,
    createdAt: date,
    updatedAt: date,
  };
  const owner: Membership = {
    id: randomUUID(),
    orgId: org.id,
    userId: caller.user.id,
    status: MemberStatus.Confirmed,
    type: MemberType.Owner,
    accessAll: true,
    akey: input.key,
    revokedStatus: null,
    invitedBy: null,
    createdAt: date,
    updatedAt: date,
  };
  const collectionName = input.collectionName?.trim();
  await commit(deps, caller, date, usersChange(), async (tx) => {
    await saveOrganization(tx, org);
    await saveMemberships(tx, [owner]);
    if (collectionName) {
      await insertCollections(tx, [{ id: randomUUID(), orgId: org.id, name: collectionName, externalId: null, createdAt: date, updatedAt: date }]);
    }
  });
  return organizationJson(org);
}

export async function organizationById(deps: Deps, caller: Caller, orgId: string) {
  return organizationJson((await requireOrg(deps.db, caller.user.id, orgId, 'owner')).org);
}

export async function updateOrganization(deps: Deps, caller: Caller, orgId: string, input: { name?: string; billingEmail?: string }) {
  const { org } = await requireOrg(deps.db, caller.user.id, orgId, 'owner');
  const date = now();
  const updated = { ...org, name: input.name ?? org.name, billingEmail: input.billingEmail ?? org.billingEmail, updatedAt: date };
  await commit(deps, caller, date, orgChange(orgId), (tx) => saveOrganization(tx, updated));
  return organizationJson(updated);
}

// Removes the organization with its ciphers and their files.
export async function deleteOrganization(deps: Deps, caller: Caller, orgId: string, masterPasswordHash: string | null | undefined) {
  await requireOrg(deps.db, caller.user.id, orgId, 'owner');
  await requireMasterPassword(caller.user, masterPasswordHash);
  const [members, cipherIds] = await Promise.all([listMembers(deps.db, orgId), listCipherIds(deps.db, { orgId })]);
  const attachments = [...(await listAttachments(deps.db, cipherIds)).values()].flat();
  await commit(deps, caller, now(), usersChange(...members.map((member) => member.userId)), (tx) => deleteOrganizationRow(tx, orgId));
  await removeAttachmentFiles(deps.blobs, attachments);
}

// Also declines a pending invitation.
export async function leaveOrganization(deps: Deps, caller: Caller, orgId: string): Promise<void> {
  const { membership } = await requireOrg(deps.db, caller.user.id, orgId, 'member');
  if (await isLastOwner(deps.db, membership)) throw badRequest("The last owner can't leave");
  await commit(deps, caller, now(), usersChange(), (tx) => deleteMembership(tx, membership.id));
}

export async function organizationPublicKey(deps: Deps, caller: Caller, orgId: string) {
  const { org } = await requireOrg(deps.db, caller.user.id, orgId, 'member');
  return { object: 'organizationPublicKey', publicKey: org.publicKey };
}

// For organizations created before they had a key pair.
export async function setOrganizationKeys(
  deps: Deps,
  caller: Caller,
  orgId: string,
  input: { publicKey: string; encryptedPrivateKey: string },
) {
  const { org } = await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  if (org.publicKey && org.privateKey) throw badRequest('Organization Keys already exist');
  const date = now();
  const updated = { ...org, publicKey: input.publicKey, privateKey: input.encryptedPrivateKey, updatedAt: date };
  await commit(deps, caller, date, orgChange(orgId), (tx) => saveOrganization(tx, updated));
  return { object: 'organizationKeys', publicKey: updated.publicKey, privateKey: updated.privateKey };
}

// Anyone may encrypt to a user; the key is public.
export async function userPublicKey(deps: Deps, userId: string) {
  const user = await findUserById(deps.db, userId);
  if (!user?.publicKey) throw notFound('User not found');
  return { userId: user.id, publicKey: user.publicKey, object: 'userKey' };
}

// The caller's pending invitations, for the web vault.
export async function invitations(deps: Deps, caller: Caller) {
  const pending = (await listUserMemberships(deps.db, caller.user.id)).filter(
    (membership) => membership.status === MemberStatus.Invited || membership.status === MemberStatus.Accepted,
  );
  const orgs = new Map((await listOrganizations(deps.db, pending.map((membership) => membership.orgId))).map((org) => [org.id, org]));
  const inviters = new Map<string, string | null>();
  for (const invitedBy of new Set(pending.map((membership) => membership.invitedBy))) {
    if (invitedBy) inviters.set(invitedBy, (await findUserById(deps.db, invitedBy))?.email ?? null);
  }
  return pending.flatMap((membership) => {
    const org = orgs.get(membership.orgId);
    if (!org) return [];
    return [
      {
        id: membership.id,
        organizationId: org.id,
        organizationName: org.name,
        status: membership.status,
        type: membership.type,
        invitedByEmail: (membership.invitedBy && inviters.get(membership.invitedBy)) ?? null,
        object: 'organizationInvitation',
      },
    ];
  });
}

export async function acceptInvitation(deps: Deps, caller: Caller, orgId: string, memberId: string): Promise<void> {
  const membership = await findMembership(deps.db, memberId);
  if (!membership || membership.orgId !== orgId || membership.userId !== caller.user.id) throw notFound('Invitation not found');
  if (membership.status !== MemberStatus.Invited) throw badRequest('Invitation already accepted');
  const date = now();
  await commit(deps, caller, date, orgChange(orgId), (tx) =>
    saveMemberships(tx, [{ ...membership, status: MemberStatus.Accepted, updatedAt: date }]),
  );
}

// The organizations in the user's profile.
export async function profileOrganizations(db: Executor, userId: string) {
  const memberships = await listUserMemberships(db, userId);
  const orgs = await listOrganizations(db, [...new Set(memberships.map((membership) => membership.orgId))]);
  return profileOrganizationsJson(memberships, orgs);
}

const MASTER_PASSWORD_POLICY = 1;

// Policies are not supported: every policy reads as disabled.
export function disabledPolicy(orgId: string, type: string) {
  return {
    id: null,
    organizationId: orgId,
    type: type.toLowerCase() === 'master-password' ? MASTER_PASSWORD_POLICY : Number(type),
    data: null,
    enabled: false,
    object: 'policy',
  };
}
