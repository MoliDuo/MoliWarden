import { isEncString } from '../../platform/enc-string';
import type { Attachment } from '../attachments/repo';
import type { CipherAccess } from '../organizations/access';
import { CipherType, TYPE_PARTS, type Cipher } from './model';

// How clients see a cipher: what the client wrote, plus what the server
// decides (ownership, dates, the viewer's rights).

export function attachmentJson(attachment: Attachment) {
  return {
    id: attachment.id,
    url: `/api/ciphers/${attachment.cipherId}/attachment/${attachment.id}`,
    fileName: attachment.fileName,
    key: attachment.key,
    // Clients read the size as a string.
    size: String(attachment.size),
    sizeName: attachment.sizeName,
    object: 'attachment',
  };
}

function content(cipher: Cipher, attachments: Attachment[]) {
  const own = TYPE_PARTS[cipher.type];
  const part = (name: keyof typeof cipher.data) => (name === own ? cipher.data[name] : null);
  const listed = attachments.filter((attachment) => isEncString(attachment.fileName)).map(attachmentJson);
  return {
    id: cipher.id,
    organizationId: cipher.organizationId,
    type: cipher.type,
    name: cipher.name,
    notes: cipher.notes,
    key: cipher.key,
    reprompt: cipher.reprompt,
    login: part('login'),
    secureNote: cipher.type === CipherType.SecureNote ? (cipher.data.secureNote ?? { type: 0 }) : null,
    card: part('card'),
    identity: part('identity'),
    sshKey: part('sshKey'),
    bankAccount: part('bankAccount'),
    driversLicense: part('driversLicense'),
    passport: part('passport'),
    fields: cipher.data.fields,
    passwordHistory: cipher.data.passwordHistory,
    attachments: listed.length ? listed : null,
    organizationUseTotp: true,
    creationDate: cipher.createdAt,
    revisionDate: cipher.updatedAt,
    deletedDate: cipher.deletedAt,
  };
}

// A cipher as the given user sees it.
export function cipherJson(cipher: Cipher, access: CipherAccess, attachments: Attachment[] = []) {
  const canEdit = access.edit || access.manage;
  return {
    ...content(cipher, attachments),
    folderId: cipher.folderId,
    favorite: cipher.favorite,
    archivedDate: cipher.archivedAt,
    edit: canEdit,
    viewPassword: access.viewPassword,
    permissions: { delete: canEdit, restore: canEdit },
    collectionIds: access.collectionIds,
    object: 'cipherDetails',
  };
}

// An organization cipher as its admins list it: nobody's folder or favorite.
export function orgCipherJson(cipher: Cipher, collectionIds: string[], attachments: Attachment[] = []) {
  return { ...content(cipher, attachments), collectionIds, object: 'cipherMiniDetails' };
}

