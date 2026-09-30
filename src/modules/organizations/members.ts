import { randomUUID } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, forbidden, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { findUserByEmail } from '../accounts/repo';
import { PushType } from '../push/service';
import { commit } from '../sync/changes';
import { hasFullAccess, isAdminType } from './access';
import {
  countOwners,
  deleteMembership,
  findMembershipOf,
  listCollections,
  listMembers,
  listOrgGrants,
  MemberStatus,
  MemberType,
  replaceGrants,
  saveMemberships,
  type CollectionGrant,
  type Member,
  type Membership,
} from './repo';
import { memberDetailsJson, memberMiniJson } from './responses';
import type { EditMemberInput, GrantInput, InviteInput, Role } from './schemas';
import { now, requireOrg, requireOwnerFor, usersChange, type Guarded } from './service';

// The members of an organization, as its admins manage them. Bulk
// operations report an error per member and apply the rest.

export interface Outcome {
  id: string;
  error: string;
}

const MEMBER_NOT_FOUND = 'Member not found';

// Admins see every collection; so do custom members given every collection
// permission.
function seesAllCollections(role: Role, permissions: InviteInput['permissions']): boolean {
  if (isAdminType(role.type)) return true;
  return (
    role.custom &&
    permissions?.editAnyCollection === true &&
    permissions?.deleteAnyCollection === true &&
    permissions?.createNewCollections === true
  );
}

async function memberGrants(db: Executor, orgId: string, membershipId: string, grants: GrantInput[]): Promise<CollectionGrant[]> {
  if (!grants.length) return [];
  const collections = new Set((await listCollections(db, [orgId])).map((collection) => collection.id));
  if (grants.some((grant) => !collections.has(grant.id))) throw badRequest('Collection not found in Organization');
  return grants.map((grant) => ({ ...grant, collectionId: grant.id, membershipId }));
}

function grantsByMember(grants: CollectionGrant[]): Map<string, CollectionGrant[]> {
  const byMember = new Map<string, CollectionGrant[]>();
  for (const grant of grants) byMember.set(grant.membershipId, [...(byMember.get(grant.membershipId) ?? []), grant]);
  return byMember;
}

export async function membersJson(deps: Deps, caller: Caller, orgId: string, includeCollections: boolean) {
  const { membership } = await requireOrg(deps.db, caller.user.id, orgId, 'manager');
  if (!hasFullAccess(membership)) throw notFound('Resource not found.');
  const [members, grants] = await Promise.all([listMembers(deps.db, orgId), listOrgGrants(deps.db, orgId)]);
  const byMember = grantsByMember(grants);
  return members.map((member) => memberDetailsJson(member, byMember.get(member.id) ?? [], includeCollections));
}

export async function membersMiniJson(deps: Deps, caller: Caller, orgId: string) {
  await requireOrg(deps.db, caller.user.id, orgId, 'manager');
  return (await listMembers(deps.db, orgId)).map(memberMiniJson);
}

async function requireMember(db: Executor, orgId: string, memberId: string): Promise<Member> {
  const member = (await listMembers(db, orgId)).find((candidate) => candidate.id === memberId);
  if (!member) throw notFound(MEMBER_NOT_FOUND);
  return member;
}

export async function memberById(deps: Deps, caller: Caller, orgId: string, memberId: string) {
  await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const [member, grants] = await Promise.all([requireMember(deps.db, orgId, memberId), listOrgGrants(deps.db, orgId)]);
  return memberDetailsJson(member, grantsByMember(grants).get(member.id) ?? [], true);
}

// Invites registered users; they accept in their web vault, then an admin
// confirms them with the organization key encrypted to them.
export async function inviteMembers(deps: Deps, caller: Caller, orgId: string, input: InviteInput): Promise<void> {
  const guarded = await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  requireOwnerFor(guarded, input.type.type, 'Only Owners can invite Managers, Admins or Owners');
  const accessAll = seesAllCollections(input.type, input.permissions);
  const date = now();
  const memberships: Membership[] = [];
  const grants: CollectionGrant[] = [];
  for (const email of input.emails) {
    const user = await findUserByEmail(deps.db, email);
    if (!user || user.status !== 'active') throw badRequest(`User does not exist: ${email}`);
    if (await findMembershipOf(deps.db, orgId, user.id)) throw badRequest(`User already in organization: ${email}`);
    const membership: Membership = {
      id: randomUUID(),
      orgId,
      userId: user.id,
      status: MemberStatus.Invited,
      type: input.type.type,
      accessAll,
      akey: null,
      revokedStatus: null,
      invitedBy: caller.user.id,
      createdAt: date,
      updatedAt: date,
    };
    memberships.push(membership);
    grants.push(...(await memberGrants(deps.db, orgId, membership.id, accessAll ? [] : input.collections)));
  }
  await commit(deps, caller, date, usersChange(...memberships.map((membership) => membership.userId)), async (tx) => {
    await saveMemberships(tx, memberships);
    await replaceGrants(tx, { membershipIds: [] }, grants);
  });
}

// There is no email to send again: the invitation stays in the invitee's
// web vault.
export async function reinviteMember(deps: Deps, caller: Caller, orgId: string, memberId: string): Promise<void> {
  await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const member = await requireMember(deps.db, orgId, memberId);
  if (member.status !== MemberStatus.Invited) throw badRequest('The user already accepted or was already invited');
}

// Hands accepted members the organization key, encrypted to them.
export async function confirmMembers(
  deps: Deps,
  caller: Caller,
  orgId: string,
  entries: Array<{ id: string; key?: string | null }>,
): Promise<Outcome[]> {
  const guarded = await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const members = new Map((await listMembers(deps.db, orgId)).map((member) => [member.id, member]));
  const date = now();
  const confirmed: Membership[] = [];
  const outcomes = entries.map(({ id, key }) => {
    const member = members.get(id);
    let error = '';
    if (!key) error = 'Invalid key provided';
    else if (!member) error = MEMBER_NOT_FOUND;
    else if (member.type !== MemberType.User && guarded.membership.type !== MemberType.Owner) {
      error = 'Only Owners can confirm Managers, Admins or Owners';
    } else if (member.status !== MemberStatus.Accepted) error = 'User in invalid state';
    else confirmed.push({ ...member, status: MemberStatus.Confirmed, akey: key, updatedAt: date });
    return { id, error };
  });
  await commit(
    deps,
    caller,
    date,
    { orgIds: [orgId], userIds: confirmed.map((member) => member.userId), push: { type: PushType.SyncVault } },
    (tx) => saveMemberships(tx, confirmed),
  );
  return outcomes;
}

export async function memberPublicKeys(deps: Deps, caller: Caller, orgId: string, ids: string[]) {
  await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const wanted = new Set(ids);
  return (await listMembers(deps.db, orgId))
    .filter((member) => wanted.has(member.id))
    .map((member) => ({ object: 'organizationUserPublicKeyResponseModel', id: member.id, userId: member.userId, key: member.publicKey }));
}

export async function editMember(deps: Deps, caller: Caller, orgId: string, memberId: string, input: EditMemberInput): Promise<void> {
  const guarded = await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const member = await requireMember(deps.db, orgId, memberId);
  const role = input.type ?? { type: member.type, custom: false };
  const callerIsOwner = guarded.membership.type === MemberType.Owner;
  if (role.type !== member.type && (isAdminType(role.type) || isAdminType(member.type)) && !callerIsOwner) {
    throw forbidden('Only Owners can grant and remove Admin or Owner privileges');
  }
  if (member.type === MemberType.Owner && !callerIsOwner) throw forbidden('Only Owners can edit Owner users');
  if (
    member.type === MemberType.Owner &&
    role.type !== MemberType.Owner &&
    member.status === MemberStatus.Confirmed &&
    (await countOwners(deps.db, orgId)) <= 1
  ) {
    throw badRequest("Can't delete the last owner");
  }
  const accessAll = seesAllCollections(role, input.permissions);
  const grants = await memberGrants(deps.db, orgId, member.id, accessAll ? [] : input.collections);
  const date = now();
  await commit(deps, caller, date, usersChange(member.userId), async (tx) => {
    await saveMemberships(tx, [{ ...member, type: role.type, accessAll, updatedAt: date }]);
    await replaceGrants(tx, { membershipIds: [member.id] }, grants);
  });
}

// Checks the members one by one; an organization keeps a confirmed owner.
async function plan(
  db: Executor,
  guarded: Guarded,
  ids: string[],
  check: (member: Member, ownersLeft: number) => string,
): Promise<{ outcomes: Outcome[]; accepted: Member[] }> {
  const members = new Map((await listMembers(db, guarded.org.id)).map((member) => [member.id, member]));
  let ownersLeft = await countOwners(db, guarded.org.id);
  const accepted: Member[] = [];
  const outcomes = ids.map((id) => {
    const member = members.get(id);
    const error = member ? check(member, ownersLeft) : MEMBER_NOT_FOUND;
    if (member && !error) {
      accepted.push(member);
      if (member.type === MemberType.Owner && member.status === MemberStatus.Confirmed) ownersLeft -= 1;
    }
    return { id, error };
  });
  return { outcomes, accepted };
}

const isLastConfirmedOwner = (member: Member, ownersLeft: number) =>
  member.type === MemberType.Owner && member.status === MemberStatus.Confirmed && ownersLeft <= 1;

export async function removeMembers(deps: Deps, caller: Caller, orgId: string, ids: string[]): Promise<Outcome[]> {
  const guarded = await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const { outcomes, accepted } = await plan(deps.db, guarded, ids, (member, ownersLeft) => {
    if (member.type !== MemberType.User && guarded.membership.type !== MemberType.Owner) return 'Only Owners can delete Admins or Owners';
    return isLastConfirmedOwner(member, ownersLeft) ? "Can't delete the last owner" : '';
  });
  await commit(
    deps,
    caller,
    now(),
    { orgIds: [orgId], userIds: accepted.map((member) => member.userId), push: { type: PushType.SyncVault } },
    async (tx) => {
      for (const member of accepted) await deleteMembership(tx, member.id);
    },
  );
  return outcomes;
}

// Revoked members keep their place and see nothing until restored.
export async function setRevoked(deps: Deps, caller: Caller, orgId: string, ids: string[], revoke: boolean): Promise<Outcome[]> {
  const guarded = await requireOrg(deps.db, caller.user.id, orgId, 'admin');
  const { outcomes, accepted } = await plan(deps.db, guarded, ids, (member, ownersLeft) => {
    if (member.userId === caller.user.id) return revoke ? 'You cannot revoke yourself' : 'You cannot restore yourself';
    if (member.type === MemberType.Owner && guarded.membership.type !== MemberType.Owner) {
      return 'Only owners can revoke or restore other owners';
    }
    if (!revoke) return member.status === MemberStatus.Revoked ? '' : 'User is already active';
    if (member.status === MemberStatus.Revoked) return 'Already revoked';
    return isLastConfirmedOwner(member, ownersLeft) ? 'Organization must have at least one confirmed owner' : '';
  });
  const date = now();
  const changed = accepted.map((member) =>
    revoke
      ? { ...member, status: MemberStatus.Revoked, revokedStatus: member.status, updatedAt: date }
      : { ...member, status: member.revokedStatus ?? MemberStatus.Accepted, revokedStatus: null, updatedAt: date },
  );
  await commit(
    deps,
    caller,
    date,
    { orgIds: [orgId], userIds: changed.map((member) => member.userId), push: { type: PushType.SyncVault } },
    (tx) => saveMemberships(tx, changed),
  );
  return outcomes;
}

// A single-member operation fails with the member's error.
export function single([outcome]: Outcome[]): void {
  if (!outcome?.error) return;
  throw outcome.error === MEMBER_NOT_FOUND ? notFound(outcome.error) : badRequest(outcome.error);
}
