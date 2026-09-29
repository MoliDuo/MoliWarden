import type { ProfileOrganizations } from '../modules/accounts/profile';
import { buildProfileOrganizations } from '../services/org-json';
import { getOrganizationsByIds, listMembershipsByUser, type OrgMembership } from '../services/storage-org-repo';

export async function loadProfileOrganizations(db: D1Database, userId: string, memberships?: OrgMembership[]): Promise<ProfileOrganizations> {
  const list = memberships || (await listMembershipsByUser(db, userId));
  const orgs = await getOrganizationsByIds(db, Array.from(new Set(list.map((membership) => membership.orgId))));
  return buildProfileOrganizations(list, new Map(orgs.map((org) => [org.id, org])));
}
