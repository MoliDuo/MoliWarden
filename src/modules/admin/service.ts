import { randomBytes } from 'node:crypto';
import type { Caller } from '../../http/authenticate';
import { badRequest, conflict, notFound } from '../../http/errors';
import { listJson } from '../../http/list';
import type { Deps } from '../../main/deps';
import type { User } from '../../types';
import { findUserById } from '../accounts/repo';
import { removeAttachmentFiles } from '../attachments/files';
import { listAttachments } from '../attachments/repo';
import { recordAudit, requestMetadata } from '../audit/service';
import { requireMasterPassword } from '../auth/password';
import { endAllSessions } from '../auth/sessions';
import { listCipherIds } from '../ciphers/repo';
import { deleteOrganization, findOrganization, listMembers, listUserMemberships } from '../organizations/repo';
import { isLastOwner } from '../organizations/service';
import { listSends } from '../sends/repo';
import { removeSendFiles } from '../sends/service';
import { usersWithSecondFactor } from '../two-factor/service';
import { deleteInvite, deleteInvites, deleteUser, insertInvite, listInvites, listUsers, setUserStatus, type Invite } from './repo';

// Accounts and invites, managed by admins. Everything that changes an
// account is confirmed with the admin's master password and audited.

function audit(deps: Deps, caller: Caller, action: string, target: { type: string; id?: string }, metadata = {}) {
  const onUser = target.type === 'user';
  return recordAudit(deps.db, {
    actorUserId: caller.user.id,
    action,
    category: onUser ? 'security' : 'system',
    level: onUser ? 'security' : 'info',
    targetType: target.type,
    targetId: target.id ?? null,
    metadata: { ...metadata, ...requestMetadata(caller.request) },
  });
}

async function requireOtherUser(deps: Deps, caller: Caller, id: string, selfMessage: string): Promise<User> {
  if (id === caller.user.id) throw badRequest(selfMessage);
  const user = await findUserById(deps.db, id);
  if (!user) throw notFound('User not found');
  return user;
}

export async function usersJson(deps: Deps) {
  const users = await listUsers(deps.db);
  const withSecondFactor = await usersWithSecondFactor(deps.db, users);
  return listJson(
    users.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      twoFactorEnabled: withSecondFactor.has(user.id),
      creationDate: user.createdAt,
      revisionDate: user.updatedAt,
      object: 'user',
    })),
  );
}

// A banned user is signed out everywhere; requests with a token issued
// before are refused too, since each checks the account's status.
export async function changeUserStatus(deps: Deps, caller: Caller, id: string, input: { status: User['status']; masterPasswordHash?: string | null }) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const user = await requireOtherUser(deps, caller, id, 'You cannot ban yourself');
  await deps.db.transaction().execute(async (tx) => {
    await setUserStatus(tx, user.id, input.status);
    if (input.status === 'banned') await endAllSessions(tx, user.id);
  });
  await audit(deps, caller, 'admin.user.status', { type: 'user', id: user.id }, { status: input.status });
  return { id: user.id, email: user.email, role: user.role, status: input.status, object: 'user' };
}

// Organizations the user is the only member of go with them. Being the
// last owner of one that has other members refuses the deletion.
async function soleMemberOrganizations(deps: Deps, userId: string): Promise<string[]> {
  const sole: string[] = [];
  for (const membership of await listUserMemberships(deps.db, userId)) {
    if ((await listMembers(deps.db, membership.orgId)).length === 1) {
      sole.push(membership.orgId);
    } else if (await isLastOwner(deps.db, membership)) {
      const org = await findOrganization(deps.db, membership.orgId);
      throw conflict(
        `User is the last owner of organization "${org?.name ?? membership.orgId}". Transfer ownership or delete the organization first.`,
      );
    }
  }
  return sole;
}

export async function removeUser(deps: Deps, caller: Caller, id: string, masterPasswordHash?: string | null): Promise<void> {
  await requireMasterPassword(caller.user, masterPasswordHash);
  const user = await requireOtherUser(deps, caller, id, 'You cannot delete yourself');
  const orgIds = await soleMemberOrganizations(deps, user.id);

  // The files are removed once the rows are gone.
  const cipherIds = (
    await Promise.all([listCipherIds(deps.db, { userId: user.id }), ...orgIds.map((orgId) => listCipherIds(deps.db, { orgId }))])
  ).flat();
  const [attachments, sends] = await Promise.all([listAttachments(deps.db, cipherIds), listSends(deps.db, user.id)]);

  await deps.db.transaction().execute(async (tx) => {
    for (const orgId of orgIds) await deleteOrganization(tx, orgId);
    await deleteUser(tx, user.id);
  });
  await removeAttachmentFiles(deps.blobs, [...attachments.values()].flat());
  await removeSendFiles(deps.blobs, sends);
  await audit(deps, caller, 'admin.user.delete', { type: 'user', id: user.id }, { targetEmail: user.email });
}

const inviteJson = (origin: string, invite: Invite) => ({
  code: invite.code,
  status: invite.status,
  createdBy: invite.createdBy,
  usedBy: invite.usedBy,
  createdAt: invite.createdAt,
  updatedAt: invite.updatedAt,
  expiresAt: invite.expiresAt,
  inviteLink: `${origin}/?invite=${encodeURIComponent(invite.code)}`,
  object: 'invite',
});

export async function invitesJson(deps: Deps, origin: string, all: boolean) {
  return listJson((await listInvites(deps.db, all)).map((invite) => inviteJson(origin, invite)));
}

export async function createInvite(deps: Deps, caller: Caller, origin: string, input: { expiresInHours: number; masterPasswordHash?: string | null }) {
  await requireMasterPassword(caller.user, input.masterPasswordHash);
  const now = new Date();
  const invite: Invite = {
    code: randomBytes(20).toString('hex'),
    createdBy: caller.user.id,
    usedBy: null,
    status: 'active',
    expiresAt: new Date(now.getTime() + input.expiresInHours * 3_600_000).toISOString(),
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
  await insertInvite(deps.db, invite);
  await audit(deps, caller, 'admin.invite.create', { type: 'invite' }, { expiresInHours: input.expiresInHours });
  return inviteJson(origin, invite);
}

export async function removeInvite(deps: Deps, caller: Caller, code: string, masterPasswordHash?: string | null): Promise<void> {
  await requireMasterPassword(caller.user, masterPasswordHash);
  if (!(await deleteInvite(deps.db, code))) throw notFound('Invite not found');
  await audit(deps, caller, 'admin.invite.delete', { type: 'invite' });
}

// Without `all`, only the used and expired invites.
export async function removeInvites(deps: Deps, caller: Caller, all: boolean, masterPasswordHash?: string | null) {
  await requireMasterPassword(caller.user, masterPasswordHash);
  const deleted = await deleteInvites(deps.db, all);
  await audit(deps, caller, all ? 'admin.invite.delete_all' : 'admin.invite.delete_invalid', { type: 'invite' }, { deleted });
  return { deleted };
}
