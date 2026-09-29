import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from '@simplewebauthn/server';
import type { Config } from '../../main/config';
import { fromBase64url } from '../../platform/crypto';
import type { AccountPasskeyCredential, AccountPasskeyPrfStatus, WebAuthnPrfDecryptionOption } from '../../types';
import { getConfiguredWebAuthnAllowedOrigins } from '../../utils/origins';

// Translation between what clients send and what @simplewebauthn expects,
// and between stored credentials and the shapes clients read.

export interface RelyingParty {
  rpId: string;
  rpName: string;
  origins: string[];
}

// WEBAUTHN_RP_ID pins the relying party; without it, the host the request
// was sent to is used. Browser extensions and the desktop app sign in from
// their own origins, which are allowed as well.
export function relyingParty(config: Config, request: Request): RelyingParty {
  const url = new URL(request.url);
  const origins = new Set([url.origin, ...getConfiguredWebAuthnAllowedOrigins({ WEBAUTHN_ALLOWED_ORIGINS: config.webauthn.allowedOrigins })]);
  return {
    rpId: config.webauthn.rpId || url.hostname,
    rpName: config.webauthn.rpName || 'MoliWarden',
    origins: [...origins],
  };
}

// Official clients use the user id's .NET GUID byte order as the WebAuthn
// user handle.
const GUID_ORDER = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];

export function userHandleFor(userId: string): Uint8Array<ArrayBuffer> {
  const hex = userId.replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(hex)) return new TextEncoder().encode(userId);
  const bytes = Buffer.from(hex, 'hex');
  return new Uint8Array(GUID_ORDER.map((index) => bytes[index]));
}

export function userIdFromHandle(handle: string | undefined): string | null {
  const bytes = handle ? fromBase64url(handle) : null;
  if (!bytes?.length) return null;
  if (bytes.length !== 16) return bytes.toString('utf8').trim() || null;
  const hex = Buffer.from(GUID_ORDER.map((index) => bytes[index])).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Clients send base64 or base64url, padded or not.
function b64url(value: unknown): string {
  return String(value ?? '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

type Json = Record<string, any>;
const record = (value: unknown): Json | null => (value && typeof value === 'object' ? (value as Json) : null);

export function toRegistrationResponse(raw: unknown): RegistrationResponseJSON | null {
  const input = record(raw);
  const response = record(input?.response);
  const clientDataJSON = response?.clientDataJSON ?? response?.clientDataJson;
  if (!input?.id || !input.rawId || !response?.attestationObject || !clientDataJSON) return null;
  return {
    id: b64url(input.id),
    rawId: b64url(input.rawId),
    type: 'public-key',
    authenticatorAttachment: input.authenticatorAttachment,
    clientExtensionResults: input.clientExtensionResults ?? input.extensions ?? {},
    response: {
      attestationObject: b64url(response.attestationObject),
      clientDataJSON: b64url(clientDataJSON),
      authenticatorData: response.authenticatorData ? b64url(response.authenticatorData) : undefined,
      transports: Array.isArray(response.transports) ? (response.transports.map(String) as AuthenticatorTransportFuture[]) : undefined,
      publicKey: response.publicKey ? b64url(response.publicKey) : undefined,
      publicKeyAlgorithm: typeof response.publicKeyAlgorithm === 'number' ? response.publicKeyAlgorithm : undefined,
    },
  };
}

export function toAuthenticationResponse(raw: unknown): AuthenticationResponseJSON | null {
  const input = record(raw);
  const response = record(input?.response);
  const clientDataJSON = response?.clientDataJSON ?? response?.clientDataJson;
  if (!input?.id || !input.rawId || !response?.authenticatorData || !response.signature || !clientDataJSON) return null;
  return {
    id: b64url(input.id),
    rawId: b64url(input.rawId),
    type: 'public-key',
    authenticatorAttachment: input.authenticatorAttachment,
    clientExtensionResults: input.clientExtensionResults ?? input.extensions ?? {},
    response: {
      authenticatorData: b64url(response.authenticatorData),
      clientDataJSON: b64url(clientDataJSON),
      signature: b64url(response.signature),
      userHandle: response.userHandle ? b64url(response.userHandle) : undefined,
    },
  };
}

// The challenge a response answers, read from its client data.
export function challengeOf(response: { response: { clientDataJSON: string } }): string | null {
  try {
    const clientData = JSON.parse(fromBase64url(response.response.clientDataJSON)?.toString('utf8') ?? '');
    return typeof clientData?.challenge === 'string' && clientData.challenge ? clientData.challenge : null;
  } catch {
    return null;
  }
}

export function toVerifiable(credential: AccountPasskeyCredential): WebAuthnCredential {
  return {
    id: credential.credentialId,
    publicKey: new Uint8Array(fromBase64url(credential.publicKey) ?? []),
    counter: credential.counter,
    transports: (credential.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined,
  };
}

export function descriptorOf(credential: AccountPasskeyCredential) {
  return { id: credential.credentialId, transports: (credential.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined };
}

// 0: the passkey can unlock the vault, 1: it could but has no keys yet,
// 2: the authenticator has no PRF support.
export function prfStatus(credential: AccountPasskeyCredential): AccountPasskeyPrfStatus {
  if (!credential.supportsPrf) return 2;
  return credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey ? 0 : 1;
}

// Sent with a passkey login so the client can unlock with the same passkey.
export function prfDecryptionOption(credential: AccountPasskeyCredential): WebAuthnPrfDecryptionOption | null {
  if (prfStatus(credential) !== 0) return null;
  return {
    EncryptedPrivateKey: credential.encryptedPrivateKey!,
    EncryptedUserKey: credential.encryptedUserKey!,
    CredentialId: credential.credentialId,
    Transports: credential.transports ?? [],
    Object: 'webAuthnPrfDecryptionOption',
  };
}

export function accountPasskeyJson(credential: AccountPasskeyCredential): Record<string, unknown> {
  const status = prfStatus(credential);
  return {
    Id: credential.id,
    id: credential.id,
    Name: credential.name,
    name: credential.name,
    PrfStatus: status,
    prfStatus: status,
    EncryptedPublicKey: credential.encryptedPublicKey,
    encryptedPublicKey: credential.encryptedPublicKey,
    EncryptedUserKey: credential.encryptedUserKey,
    encryptedUserKey: credential.encryptedUserKey,
    CreationDate: credential.createdAt,
    RevisionDate: credential.updatedAt,
    Object: 'webauthnCredential',
    object: 'webauthnCredential',
  };
}
