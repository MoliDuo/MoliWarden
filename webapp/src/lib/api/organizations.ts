import { createApiError, parseErrorMessage, parseJson, type AuthedFetch } from './shared';
import { encryptForPublicKey, encryptWithOrgKey, generateOrganizationKeys, orgKeyBytes } from '../org-crypto';
import type { OrgKeyMap } from '../types';
import { bytesToBase64 } from '../crypto';

// Organization management API (see src/handlers/organizations.ts on the server).

export const ORG_TYPE = { OWNER: 0, ADMIN: 1, USER: 2, MANAGER: 3, CUSTOM: 4 } as const;
export const ORG_STATUS = { REVOKED: -1, INVITED: 0, ACCEPTED: 1, CONFIRMED: 2 } as const;

export interface OrgCollectionAccess {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface OrgMember {
  id: string;
  userId: string;
  name: string | null;
  email: string;
  status: number;
  type: number;
  accessAll: boolean;
  twoFactorEnabled: boolean;
  collections: OrgCollectionAccess[];
}

export interface OrgCollectionDetails {
  id: string;
  organizationId: string;
  name: string;
  decName?: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
  users: OrgCollectionAccess[];
}

export interface OrgInvitation {
  id: string;
  organizationId: string;
  organizationName: string;
  status: number;
  type: number;
  invitedByEmail: string | null;
}

async function request<T>(authedFetch: AuthedFetch, path: string, init: RequestInit & { json?: unknown } = {}, fallback = 'Request failed'): Promise<T> {
  const headers = new Headers(init.headers);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(init.json);
  }
  const resp = await authedFetch(path, { ...init, headers, body });
  if (!resp.ok) {
    throw createApiError(await parseErrorMessage(resp, fallback), resp.status);
  }
  return (await parseJson<T>(resp)) as T;
}

// Members are shown as Custom (4) by the server; the UI treats 3 and 4 as "Manager".
export function normalizeMemberType(type: number): number {
  return type === ORG_TYPE.CUSTOM ? ORG_TYPE.MANAGER : type;
}

export async function getMyPublicKey(authedFetch: AuthedFetch, userId: string): Promise<string> {
  const body = await request<{ publicKey?: string }>(authedFetch, `/api/users/${encodeURIComponent(userId)}/public-key`);
  if (!body?.publicKey) throw new Error('Account public key unavailable');
  return body.publicKey;
}

export async function createOrganization(
  authedFetch: AuthedFetch,
  args: { name: string; billingEmail: string; collectionName: string; userId: string }
): Promise<{ id: string }> {
  const publicKey = await getMyPublicKey(authedFetch, args.userId);
  const keys = await generateOrganizationKeys(publicKey);
  const tempKeys: OrgKeyMap = {
    new: {
      enc: bytesToBase64(keys.orgKey.slice(0, 32)),
      mac: bytesToBase64(keys.orgKey.slice(32, 64)),
    },
  };
  const collectionName = await encryptWithOrgKey(args.collectionName, tempKeys, 'new');
  return request(authedFetch, '/api/organizations', {
    method: 'POST',
    json: {
      name: args.name,
      billingEmail: args.billingEmail,
      key: keys.key,
      collectionName,
      keys: { publicKey: keys.publicKey, encryptedPrivateKey: keys.encryptedPrivateKey },
      planType: 0,
    },
  });
}

export async function updateOrganization(authedFetch: AuthedFetch, orgId: string, name: string, billingEmail: string): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}`, { method: 'PUT', json: { name, billingEmail } });
}

export async function deleteOrganization(authedFetch: AuthedFetch, orgId: string, masterPasswordHash: string): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}`, { method: 'DELETE', json: { masterPasswordHash } });
}

export async function leaveOrganization(authedFetch: AuthedFetch, orgId: string): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}/leave`, { method: 'POST' });
}

export async function listInvitations(authedFetch: AuthedFetch): Promise<OrgInvitation[]> {
  const body = await request<{ data?: OrgInvitation[] }>(authedFetch, '/api/organizations/invitations');
  return body?.data || [];
}

export async function acceptInvitation(authedFetch: AuthedFetch, invitation: OrgInvitation): Promise<void> {
  await request(authedFetch, `/api/organizations/${invitation.organizationId}/users/${invitation.id}/accept`, { method: 'POST', json: {} });
}

export async function listMembers(authedFetch: AuthedFetch, orgId: string): Promise<OrgMember[]> {
  const body = await request<{ data?: OrgMember[] }>(authedFetch, `/api/organizations/${orgId}/users?includeCollections=true`);
  return (body?.data || []).map((member) => ({ ...member, type: normalizeMemberType(member.type) }));
}

export async function inviteMembers(
  authedFetch: AuthedFetch,
  orgId: string,
  emails: string[],
  type: number,
  collections: OrgCollectionAccess[]
): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}/users/invite`, {
    method: 'POST',
    json: { emails, type, collections, groups: [], permissions: {} },
  });
}

export async function editMember(
  authedFetch: AuthedFetch,
  orgId: string,
  memberId: string,
  type: number,
  collections: OrgCollectionAccess[]
): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}/users/${memberId}`, {
    method: 'PUT',
    json: { type, collections, groups: [], permissions: {} },
  });
}

export async function getMemberPublicKey(authedFetch: AuthedFetch, orgId: string, memberId: string): Promise<{ userId: string; key: string }> {
  const body = await request<{ data?: Array<{ id: string; userId: string; key: string }> }>(
    authedFetch,
    `/api/organizations/${orgId}/users/public-keys`,
    { method: 'POST', json: { ids: [memberId] } }
  );
  const entry = body?.data?.find((item) => item.id === memberId);
  if (!entry?.key) throw new Error('Member public key unavailable');
  return { userId: entry.userId, key: entry.key };
}

// Wraps the org key for the member's public key and confirms them.
export async function confirmMember(
  authedFetch: AuthedFetch,
  orgId: string,
  memberId: string,
  memberPublicKey: string,
  orgKeys: OrgKeyMap
): Promise<void> {
  const key = await encryptForPublicKey(orgKeyBytes(orgKeys, orgId), memberPublicKey);
  await request(authedFetch, `/api/organizations/${orgId}/users/${memberId}/confirm`, { method: 'POST', json: { key } });
}

export async function removeMember(authedFetch: AuthedFetch, orgId: string, memberId: string): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}/users/${memberId}`, { method: 'DELETE' });
}

export async function setMemberRevoked(authedFetch: AuthedFetch, orgId: string, memberId: string, revoked: boolean): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}/users/${memberId}/${revoked ? 'revoke' : 'restore'}`, { method: 'PUT' });
}

export async function listCollectionDetails(authedFetch: AuthedFetch, orgId: string): Promise<OrgCollectionDetails[]> {
  const body = await request<{ data?: OrgCollectionDetails[] }>(authedFetch, `/api/organizations/${orgId}/collections/details`);
  return body?.data || [];
}

export async function saveCollection(
  authedFetch: AuthedFetch,
  orgId: string,
  orgKeys: OrgKeyMap,
  args: { id?: string; name: string; users: OrgCollectionAccess[] }
): Promise<void> {
  const name = await encryptWithOrgKey(args.name, orgKeys, orgId);
  const path = args.id ? `/api/organizations/${orgId}/collections/${args.id}` : `/api/organizations/${orgId}/collections`;
  await request(authedFetch, path, { method: args.id ? 'PUT' : 'POST', json: { name, users: args.users, groups: [] } });
}

export async function deleteCollection(authedFetch: AuthedFetch, orgId: string, collectionId: string): Promise<void> {
  await request(authedFetch, `/api/organizations/${orgId}/collections/${collectionId}`, { method: 'DELETE' });
}

export async function updateCipherCollections(authedFetch: AuthedFetch, cipherId: string, collectionIds: string[]): Promise<void> {
  await request(authedFetch, `/api/ciphers/${cipherId}/collections_v2`, { method: 'PUT', json: { collectionIds } });
}
