import { base64ToBytes, bytesToBase64, decryptBw, encryptBw, requireWebCrypto, toBufferSource } from './crypto';
import type { OrgKeyMap, ProfileOrganization, SessionState } from './types';

// Organization key handling in the browser.
//
// - Each confirmed member receives the 64-byte org symmetric key wrapped with
//   their RSA public key (EncString type 4: RSA-OAEP / SHA-1). Unwrapping needs
//   the member's private key, which is itself encrypted with the user key.
// - Org items are encrypted exactly like personal items, just with the org key,
//   so the existing encrypt/decrypt helpers are reused through orgSession().

const RSA_OAEP_SHA1 = { name: 'RSA-OAEP', hash: 'SHA-1' } as const;
const RSA_OAEP_SHA256 = { name: 'RSA-OAEP', hash: 'SHA-256' } as const;

function userKeys(session: SessionState): { enc: Uint8Array; mac: Uint8Array } {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  return { enc: base64ToBytes(session.symEncKey), mac: base64ToBytes(session.symMacKey) };
}

export async function decryptUserPrivateKey(encryptedPrivateKey: string, session: SessionState): Promise<Uint8Array> {
  const { enc, mac } = userKeys(session);
  return decryptBw(encryptedPrivateKey, enc, mac);
}

async function rsaDecrypt(encString: string, pkcs8: Uint8Array): Promise<Uint8Array> {
  const dot = encString.indexOf('.');
  const type = Number(encString.slice(0, dot));
  const payload = encString.slice(dot + 1).split('|')[0];
  const algorithm = type === 3 || type === 5 ? RSA_OAEP_SHA256 : RSA_OAEP_SHA1;
  if (![3, 4, 5, 6].includes(type)) throw new Error('Unsupported organization key type');
  const key = await requireWebCrypto().subtle.importKey('pkcs8', toBufferSource(pkcs8), algorithm, false, ['decrypt']);
  return new Uint8Array(await requireWebCrypto().subtle.decrypt({ name: 'RSA-OAEP' }, key, toBufferSource(base64ToBytes(payload))));
}

// Unwraps every org key the member holds. Orgs whose key cannot be decrypted
// are skipped (their items stay undecryptable instead of breaking the vault).
export async function decryptOrgKeys(
  organizations: ProfileOrganization[] | undefined,
  encryptedPrivateKey: string | null | undefined,
  session: SessionState
): Promise<OrgKeyMap> {
  const out: OrgKeyMap = {};
  const withKeys = (organizations || []).filter((org) => org.status === 2 && typeof org.key === 'string' && org.key);
  if (!withKeys.length || !encryptedPrivateKey) return out;
  const pkcs8 = await decryptUserPrivateKey(encryptedPrivateKey, session);
  for (const org of withKeys) {
    try {
      const keyBytes = await rsaDecrypt(org.key as string, pkcs8);
      if (keyBytes.length < 64) continue;
      out[org.id] = { enc: bytesToBase64(keyBytes.slice(0, 32)), mac: bytesToBase64(keyBytes.slice(32, 64)) };
    } catch (error) {
      console.warn('Failed to decrypt organization key', org.id, error);
    }
  }
  return out;
}

// A session whose "user key" is the org key, for reusing the item crypto.
export function orgSession(session: SessionState, orgKeys: OrgKeyMap, orgId: string | null | undefined): SessionState {
  if (!orgId) return session;
  const key = orgKeys[orgId];
  if (!key) throw new Error('Organization key unavailable. Reload the vault and try again.');
  return { ...session, symEncKey: key.enc, symMacKey: key.mac };
}

export async function encryptForPublicKey(data: Uint8Array, publicKeyB64: string): Promise<string> {
  const key = await requireWebCrypto().subtle.importKey('spki', toBufferSource(base64ToBytes(publicKeyB64)), RSA_OAEP_SHA1, false, ['encrypt']);
  const encrypted = new Uint8Array(await requireWebCrypto().subtle.encrypt({ name: 'RSA-OAEP' }, key, toBufferSource(data)));
  return `4.${bytesToBase64(encrypted)}`;
}

export async function encryptWithOrgKey(text: string, orgKeys: OrgKeyMap, orgId: string): Promise<string> {
  const key = orgKeys[orgId];
  if (!key) throw new Error('Organization key unavailable');
  return encryptBw(new TextEncoder().encode(text), base64ToBytes(key.enc), base64ToBytes(key.mac));
}

export async function decryptWithOrgKey(value: string | null | undefined, orgKeys: OrgKeyMap, orgId: string): Promise<string> {
  const key = orgKeys[orgId];
  if (!key || !value) return '';
  try {
    return new TextDecoder().decode(await decryptBw(value, base64ToBytes(key.enc), base64ToBytes(key.mac)));
  } catch {
    return '';
  }
}

export interface NewOrganizationKeys {
  orgKey: Uint8Array;
  // Org key wrapped for the creator (becomes their membership key).
  key: string;
  publicKey: string;
  encryptedPrivateKey: string;
}

export async function generateOrganizationKeys(creatorPublicKeyB64: string): Promise<NewOrganizationKeys> {
  const cryptoApi = requireWebCrypto();
  const orgKey = cryptoApi.getRandomValues(new Uint8Array(64));
  const pair = (await cryptoApi.subtle.generateKey(
    { ...RSA_OAEP_SHA1, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ['encrypt', 'decrypt']
  )) as CryptoKeyPair;
  const spki = new Uint8Array(await cryptoApi.subtle.exportKey('spki', pair.publicKey));
  const pkcs8 = new Uint8Array(await cryptoApi.subtle.exportKey('pkcs8', pair.privateKey));
  return {
    orgKey,
    key: await encryptForPublicKey(orgKey, creatorPublicKeyB64),
    publicKey: bytesToBase64(spki),
    encryptedPrivateKey: await encryptBw(pkcs8, orgKey.slice(0, 32), orgKey.slice(32, 64)),
  };
}

export function orgKeyBytes(orgKeys: OrgKeyMap, orgId: string): Uint8Array {
  const key = orgKeys[orgId];
  if (!key) throw new Error('Organization key unavailable');
  const out = new Uint8Array(64);
  out.set(base64ToBytes(key.enc), 0);
  out.set(base64ToBytes(key.mac), 32);
  return out;
}
