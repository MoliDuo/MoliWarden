import type { Env, User } from './types';
import { errorResponse, jsonResponse } from './utils/response';
import { listJson } from './services/org-json';
import {
  handleGetSends,
  handleGetSend,
  handleCreateSend,
  handleCreateFileSendV2,
  handleGetSendFileUpload,
  handleUploadSendFile,
  handleUpdateSend,
  handleDeleteSend,
  handleBulkDeleteSends,
  handleRemoveSendPassword,
  handleRemoveSendAuth,
} from './handlers/sends';
import {
  handleCreateAttachment,
  handleUploadAttachment,
  handleGetAttachment,
  handleUpdateAttachmentMetadata,
  handleDeleteAttachment,
} from './handlers/attachments';
import { handleAdminRoute } from './router-admin';

import {
  handleAcceptInvitation,
  handleBulkConfirmMembers,
  handleBulkDeleteCollections,
  handleBulkRemoveMembers,
  handleBulkRevokeMembers,
  handleCollectionsBulkAccess,
  handleConfirmMember,
  handleCreateCollection,
  handleCreateOrganization,
  handleDeleteCollection,
  handleDeleteOrganization,
  handleEditMember,
  handleGetCollectionDetails,
  handleGetCollectionUsers,
  handleGetMember,
  handleGetOrganization,
  handleGetOrganizationKeys,
  handleGetUserPublicKey,
  handleInviteMembers,
  handleLeaveOrganization,
  handleListMembers,
  handleListMembersMini,
  handleListMyCollections,
  handleListMyInvitations,
  handleListOrgCollectionDetails,
  handleListOrgCollections,
  handleListPolicies,
  handleGetDisabledPolicy,
  handleMembersPublicKeys,
  handleReinviteMember,
  handleRemoveMember,
  handleRevokeMember,
  handleSetOrganizationKeys,
  handleUpdateCollection,
  handleUpdateOrganization,
} from './handlers/organizations';

async function routeOrganizations(
  request: Request,
  env: Env,
  user: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (path === '/api/organizations') {
    if (method === 'POST') return handleCreateOrganization(request, env, user);
    return null;
  }
  if (path === '/api/organizations/invitations' && method === 'GET') {
    return handleListMyInvitations(env, user);
  }

  const match = path.match(/^\/api\/organizations\/([a-f0-9-]{36})(\/.*)?$/i);
  if (!match) return null;
  const orgId = match[1].toLowerCase();
  const sub = match[2] || '';

  if (sub === '' || sub === '/') {
    if (method === 'GET') return handleGetOrganization(env, user, orgId);
    if (method === 'PUT' || method === 'POST') return handleUpdateOrganization(request, env, user, orgId);
    if (method === 'DELETE') return handleDeleteOrganization(request, env, user, orgId);
    return null;
  }
  if (sub === '/delete' && method === 'POST') return handleDeleteOrganization(request, env, user, orgId);
  if (sub === '/leave' && method === 'POST') return handleLeaveOrganization(env, user, orgId);
  if ((sub === '/keys' || sub === '/public-key') && method === 'GET') return handleGetOrganizationKeys(env, user, orgId);
  if (sub === '/keys' && method === 'POST') return handleSetOrganizationKeys(request, env, user, orgId);
  if ((sub === '/policies' || sub === '/policies/token') && method === 'GET') return handleListPolicies();
  // Policies are not supported: every single policy reads as disabled.
  const policyMatch = sub.match(/^\/policies\/(\d+|master-password)$/i);
  if (policyMatch && method === 'GET') return handleGetDisabledPolicy(orgId, policyMatch[1]);
  // Billing does not exist on a self-hosted server; these only keep official
  // clients from logging 404s (same responses as Vaultwarden).
  if (sub === '/billing/metadata' && method === 'GET') return jsonResponse(listJson([]));
  if (sub === '/billing/vnext/warnings' && method === 'GET') {
    return jsonResponse({ freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null });
  }
  if (sub === '/billing/vnext/self-host/metadata' && method === 'GET') {
    return jsonResponse({ isOnSecretsManagerStandalone: false, organizationOccupiedSeats: 0 });
  }

  // Members
  if (sub === '/users') {
    if (method === 'GET') return handleListMembers(request, env, user, orgId);
    if (method === 'DELETE') return handleBulkRemoveMembers(request, env, user, orgId);
    return null;
  }
  if (sub === '/users/mini-details' && method === 'GET') return handleListMembersMini(env, user, orgId);
  if (sub === '/users/invite' && method === 'POST') return handleInviteMembers(request, env, user, orgId);
  if (sub === '/users/confirm' && method === 'POST') return handleBulkConfirmMembers(request, env, user, orgId);
  if (sub === '/users/public-keys' && method === 'POST') return handleMembersPublicKeys(request, env, user, orgId);
  if (sub === '/users/revoke' && method === 'PUT') return handleBulkRevokeMembers(request, env, user, orgId, true);
  if (sub === '/users/restore' && method === 'PUT') return handleBulkRevokeMembers(request, env, user, orgId, false);

  const memberMatch = sub.match(/^\/users\/([a-f0-9-]{36})(\/.*)?$/i);
  if (memberMatch) {
    const memberId = memberMatch[1].toLowerCase();
    const action = memberMatch[2] || '';
    if (action === '') {
      if (method === 'GET') return handleGetMember(env, user, orgId, memberId);
      if (method === 'PUT' || method === 'POST') return handleEditMember(request, env, user, orgId, memberId);
      if (method === 'DELETE') return handleRemoveMember(env, user, orgId, memberId);
      return null;
    }
    if (action === '/delete' && method === 'POST') return handleRemoveMember(env, user, orgId, memberId);
    if (action === '/accept' && method === 'POST') return handleAcceptInvitation(env, user, orgId, memberId);
    if (action === '/reinvite' && method === 'POST') return handleReinviteMember(env, user, orgId, memberId);
    if (action === '/confirm' && method === 'POST') return handleConfirmMember(request, env, user, orgId, memberId);
    if (action === '/revoke' && method === 'PUT') return handleRevokeMember(env, user, orgId, memberId, true);
    if ((action === '/restore' || action === '/restore/vnext') && method === 'PUT') {
      return handleRevokeMember(env, user, orgId, memberId, false);
    }
    return null;
  }

  // Collections
  if (sub === '/collections') {
    if (method === 'GET') return handleListOrgCollections(env, user, orgId);
    if (method === 'POST') return handleCreateCollection(request, env, user, orgId);
    if (method === 'DELETE') return handleBulkDeleteCollections(request, env, user, orgId);
    return null;
  }
  if (sub === '/collections/details' && method === 'GET') return handleListOrgCollectionDetails(env, user, orgId);
  if (sub === '/collections/bulk-access' && method === 'POST') return handleCollectionsBulkAccess(request, env, user, orgId);
  const collectionMatch = sub.match(/^\/collections\/([a-f0-9-]{36})(\/.*)?$/i);
  if (collectionMatch) {
    const collectionId = collectionMatch[1].toLowerCase();
    const action = collectionMatch[2] || '';
    if (action === '') {
      if (method === 'PUT' || method === 'POST') return handleUpdateCollection(request, env, user, orgId, collectionId);
      if (method === 'DELETE') return handleDeleteCollection(env, user, orgId, collectionId);
      return null;
    }
    if (action === '/delete' && method === 'POST') return handleDeleteCollection(env, user, orgId, collectionId);
    if (action === '/details' && method === 'GET') return handleGetCollectionDetails(env, user, orgId, collectionId);
    if (action === '/users' && method === 'GET') return handleGetCollectionUsers(env, user, orgId, collectionId);
    return null;
  }
  return null;
}


export async function handleAuthenticatedRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (path.startsWith('/notifications/')) {
    return errorResponse('Not found', 404);
  }

  const cipherMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)(\/.*)?$/i);
  if (cipherMatch) {
    const cipherId = cipherMatch[1];
    const subPath = cipherMatch[2] || '';

    if (subPath === '/attachment/v2' && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);
    if ((subPath === '/attachment' || subPath === '/attachment-admin') && method === 'POST') return handleCreateAttachment(request, env, userId, cipherId);

    const attachmentMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)$/i);
    if (attachmentMatch) {
      const attachmentId = attachmentMatch[1];
      if (method === 'POST' || method === 'PUT') return handleUploadAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'GET') return handleGetAttachment(request, env, userId, cipherId, attachmentId);
      if (method === 'DELETE') return handleDeleteAttachment(request, env, userId, cipherId, attachmentId);
    }

    const attachmentMetadataMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/metadata$/i);
    if (attachmentMetadataMatch && (method === 'POST' || method === 'PUT')) {
      return handleUpdateAttachmentMetadata(request, env, userId, cipherId, attachmentMetadataMatch[1]);
    }

    const attachmentAdminMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/admin$/i);
    if (attachmentAdminMatch && method === 'DELETE') {
      return handleDeleteAttachment(request, env, userId, cipherId, attachmentAdminMatch[1]);
    }

    const attachmentDeleteMatch = subPath.match(/^\/attachment\/([a-f0-9-]+)\/delete(?:-admin)?$/i);
    if (attachmentDeleteMatch && method === 'POST') {
      return handleDeleteAttachment(request, env, userId, cipherId, attachmentDeleteMatch[1]);
    }
  }

  if (path === '/api/collections' && method === 'GET') {
    return handleListMyCollections(env, currentUser);
  }

  if (path === '/api/organizations' || path.startsWith('/api/organizations/')) {
    const orgResponse = await routeOrganizations(request, env, currentUser, path, method);
    if (orgResponse) return orgResponse;
    return null;
  }

  if (path === '/api/sends') {
    if (method === 'GET') return handleGetSends(request, env, userId);
    if (method === 'POST') return handleCreateSend(request, env, userId);
    return null;
  }

  if (path === '/api/sends/file/v2' && method === 'POST') {
    return handleCreateFileSendV2(request, env, userId);
  }

  if (path === '/api/sends/delete' && method === 'POST') {
    return handleBulkDeleteSends(request, env, userId);
  }

  const sendMatch = path.match(/^\/api\/sends\/([^/]+)(\/.*)?$/i);
  if (sendMatch) {
    const sendId = sendMatch[1];
    const subPath = sendMatch[2] || '';

    if (subPath === '' || subPath === '/') {
      if (method === 'GET') return handleGetSend(request, env, userId, sendId);
      if (method === 'PUT') return handleUpdateSend(request, env, userId, sendId);
      if (method === 'DELETE') return handleDeleteSend(request, env, userId, sendId);
    }

    if (subPath === '/remove-password' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendPassword(request, env, userId, sendId);
    }

    if (subPath === '/remove-auth' && (method === 'PUT' || method === 'POST')) {
      return handleRemoveSendAuth(request, env, userId, sendId);
    }

    const sendFileUploadMatch = subPath.match(/^\/file\/([^/]+)\/?$/i);
    if (sendFileUploadMatch) {
      const fileId = sendFileUploadMatch[1];
      if (method === 'GET') return handleGetSendFileUpload(request, env, userId, sendId, fileId);
      if (method === 'POST' || method === 'PUT') return handleUploadSendFile(request, env, userId, sendId, fileId);
    }
  }

  // Security tasks (at-risk password reminders) are an organization feature
  // this server does not have.
  if (path === '/api/tasks' && method === 'GET') {
    return jsonResponse(listJson([]));
  }

  if (path === '/api/policies' && method === 'GET') {
    return handleListPolicies();
  }

  const publicKeyMatch = path.match(/^\/api\/users\/([a-f0-9-]+)\/public-key$/i);
  if (publicKeyMatch && method === 'GET') {
    return handleGetUserPublicKey(env, publicKeyMatch[1]);
  }

  const adminResponse = await handleAdminRoute(request, env, currentUser, path, method);
  if (adminResponse) return adminResponse;

  return null;
}
