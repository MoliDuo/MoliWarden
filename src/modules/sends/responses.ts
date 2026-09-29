import { SendAuthType, accessIdOf, type Send } from './model';

// Clients read file sizes as strings.
const fileJson = (send: Send) => send.file && { ...send.file, size: String(send.file.size) };

// Bitwarden's SendResponseModel, for the owner.
export function sendJson(send: Send) {
  return {
    id: send.id,
    accessId: accessIdOf(send.id),
    type: send.type,
    name: send.name,
    notes: send.notes,
    text: send.text,
    file: fileJson(send),
    key: send.key,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    // Clients only check whether there is one.
    password: send.password?.hash ?? null,
    emails: null,
    authType: send.password ? SendAuthType.Password : SendAuthType.None,
    disabled: send.disabled,
    hideEmail: send.hideEmail,
    revisionDate: send.updatedAt,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    object: 'send',
  };
}

// SendAccessResponseModel, for recipients.
export function sendAccessJson(send: Send, creatorEmail: string | null) {
  return {
    id: send.id,
    type: send.type,
    name: send.name,
    text: send.text,
    file: fileJson(send),
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    creatorIdentifier: send.hideEmail ? null : creatorEmail,
    object: 'send-access',
  };
}
