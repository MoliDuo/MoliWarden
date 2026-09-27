import type { Env, ProfileResponse, User } from '../types';
import { buildProfileOrganizations } from '../services/org-json';
import { getOrganizationsByIds, listMembershipsByUser, type OrgMembership } from '../services/storage-org-repo';
import { buildAccountKeys } from './user-decryption';
import { isYubiKeyEnabled } from './yubico-otp';

export interface ProfileOrganizations {
  organizations: Record<string, unknown>[];
  organizationsNew: Record<string, unknown>[];
}

export async function loadProfileOrganizations(db: D1Database, userId: string, memberships?: OrgMembership[]): Promise<ProfileOrganizations> {
  const list = memberships || (await listMembershipsByUser(db, userId));
  const orgs = await getOrganizationsByIds(db, Array.from(new Set(list.map((membership) => membership.orgId))));
  return buildProfileOrganizations(list, new Map(orgs.map((org) => [org.id, org])));
}

export async function buildProfileResponseWithOrgs(user: User, env: Env): Promise<ProfileResponse> {
  return buildProfileResponse(user, env, await loadProfileOrganizations(env.DB, user.id));
}

export function buildProfileResponse(
  user: User,
  env?: Env,
  orgs: ProfileOrganizations = { organizations: [], organizationsNew: [] }
): ProfileResponse {
  void env;
  const accountKeys = buildAccountKeys(user);

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: false,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: !!user.totpSecret || isYubiKeyEnabled(user),
    yubikeyEnabled: isYubiKeyEnabled(user),
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations: orgs.organizations,
    organizationsNew: orgs.organizationsNew,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    // New-device verification is not supported without an email delivery channel.
    // Always report disabled so clients do not present a false security posture.
    verifyDevices: false,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}
