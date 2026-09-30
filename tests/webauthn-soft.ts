// Minimal software FIDO2 authenticator for end-to-end tests.
//
// Produces `PublicKeyCredential`-shaped JSON (what browsers' toJSON() and the
// official Bitwarden clients send) for registration ("none" attestation,
// ES256 / P-256) and assertions. Only node:crypto is used.
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

// ---------------------------------------------------------------------------
// Encoding helpers

export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function fromB64url(value: string): Buffer {
  return Buffer.from(String(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url');
}

// Re-encode a base64url string as standard, padded base64 (some clients send that).
export function b64urlToB64(value: string): string {
  return fromB64url(value).toString('base64');
}

function sha256(data: Uint8Array | string): Buffer {
  return createHash('sha256').update(data).digest();
}

// ---------------------------------------------------------------------------
// Tiny CBOR encoder: unsigned/negative ints, byte strings, text, arrays, maps.

export type CborValue = number | string | Uint8Array | CborValue[] | Map<CborValue, CborValue> | { [key: string]: CborValue };

function cborHead(major: number, length: number): Buffer {
  const mt = major << 5;
  if (length < 24) return Buffer.from([mt | length]);
  if (length < 0x100) return Buffer.from([mt | 24, length]);
  if (length < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = mt | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  if (length < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = mt | 26;
    b.writeUInt32BE(length, 1);
    return b;
  }
  throw new Error('CBOR length too large');
}

export function cborEncode(value: CborValue): Buffer {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new Error('CBOR: only integers are supported');
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return Buffer.concat([cborHead(2, value.length), value]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([cborHead(4, value.length), ...value.map(cborEncode)]);
  }
  const entries: Array<[CborValue, CborValue]> = value instanceof Map ? [...value.entries()] : Object.entries(value);
  return Buffer.concat([cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [cborEncode(k), cborEncode(v)])]);
}

// ---------------------------------------------------------------------------
// Authenticator

// Server-provided options, as returned by the API (JSON, base64url fields).
export interface CreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name?: string };
  user: { id: string; name?: string; displayName?: string };
  pubKeyCredParams?: Array<{ type: string; alg: number }>;
  excludeCredentials?: Array<{ id: string; type?: string }>;
  extensions?: Record<string, any>;
  [key: string]: unknown;
}

export interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  allowCredentials?: Array<{ id: string; type?: string }>;
  userVerification?: string;
  extensions?: Record<string, any>;
  [key: string]: unknown;
}

// "w3c": the shape of PublicKeyCredential.toJSON() (clientDataJSON, clientExtensionResults).
// "bitwarden": the shape official Bitwarden clients post (clientDataJson, extensions).
export type ResponseStyle = 'w3c' | 'bitwarden';

export interface CredentialOutputOptions {
  origin: string;
  style?: ResponseStyle;
  // Encode binary fields as standard padded base64 instead of base64url.
  base64?: boolean;
  // Override pieces of clientDataJSON (type/challenge/origin) to build bad responses.
  clientData?: Partial<{ type: string; challenge: string; origin: string }>;
  // Authenticator flags (default: UP + UV).
  userVerified?: boolean;
  userPresent?: boolean;
  // Override the RP id hashed into authenticatorData.
  rpId?: string;
}

export interface AssertionOutputOptions extends CredentialOutputOptions {
  // Include response.userHandle (discoverable-credential flows).
  userHandle?: boolean;
  // Force a specific signature counter instead of the next increment.
  counter?: number;
  // Sign with a different key (the signature will not verify).
  signWith?: KeyObject;
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;

export class SoftCredential {
  readonly credentialId: Buffer;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly rpId: string;
  readonly userHandle: Buffer;
  // PRF (hmac-secret) seed; results are HMAC-SHA256(prfSeed, salt).
  readonly prfSeed = randomBytes(32);
  counter = 0;

  constructor(rpId: string, userHandle: Buffer) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.rpId = rpId;
    this.userHandle = userHandle;
    this.credentialId = randomBytes(32);
  }

  get id(): string {
    return b64url(this.credentialId);
  }

  coseKey(): Buffer {
    const jwk = this.publicKey.export({ format: 'jwk' });
    return cborEncode(new Map<CborValue, CborValue>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, fromB64url(jwk.x!)],
      [-3, fromB64url(jwk.y!)],
    ]));
  }

  prfResults(extension: any): Record<string, string> | null {
    const evalInput = extension?.eval ?? (extension?.evalByCredential ? extension.evalByCredential[this.id] : undefined);
    if (!evalInput?.first) return null;
    const results: Record<string, string> = {
      first: b64url(createHmac('sha256', this.prfSeed).update(fromB64url(evalInput.first)).digest()),
    };
    if (evalInput.second) {
      results.second = b64url(createHmac('sha256', this.prfSeed).update(fromB64url(evalInput.second)).digest());
    }
    return results;
  }
}

function encodeBinary(bytes: Uint8Array, opts: { base64?: boolean }): string {
  return opts.base64 ? Buffer.from(bytes).toString('base64') : b64url(bytes);
}

function clientDataJSON(
  type: string,
  challenge: string,
  origin: string,
  override: CredentialOutputOptions['clientData'] = {},
): Buffer {
  return Buffer.from(JSON.stringify({
    type: override.type ?? type,
    challenge: override.challenge ?? challenge,
    origin: override.origin ?? origin,
    crossOrigin: false,
  }));
}

export class SoftAuthenticator {
  readonly aaguid = Buffer.alloc(16);
  readonly credentials: SoftCredential[] = [];

  // navigator.credentials.create(): returns the new credential and its JSON response.
  create(options: CreationOptionsJSON, output: CredentialOutputOptions): { credential: SoftCredential; response: Record<string, any> } {
    const rpId = options.rp?.id;
    if (!rpId) throw new Error('creation options carry no rp.id');
    if (options.pubKeyCredParams && !options.pubKeyCredParams.some((p) => p.alg === -7)) {
      throw new Error('server does not accept ES256');
    }
    const excluded = new Set((options.excludeCredentials || []).map((c) => c.id));
    if (this.credentials.some((c) => c.rpId === rpId && excluded.has(c.id))) {
      throw new Error('InvalidStateError: credential already registered');
    }

    const credential = new SoftCredential(rpId, fromB64url(options.user.id));
    this.credentials.push(credential);

    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(credential.credentialId.length);
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(credential.counter);
    let flags = FLAG_AT;
    if (output.userPresent ?? true) flags |= FLAG_UP;
    if (output.userVerified ?? true) flags |= FLAG_UV;
    const authData = Buffer.concat([
      sha256(output.rpId ?? rpId),
      Buffer.from([flags]),
      signCount,
      this.aaguid,
      idLen,
      credential.credentialId,
      credential.coseKey(),
    ]);
    const attestationObject = cborEncode({ fmt: 'none', attStmt: {}, authData });
    const cdj = clientDataJSON('webauthn.create', options.challenge, output.origin, output.clientData);

    const extensionResults: Record<string, unknown> = {};
    if (options.extensions && 'prf' in options.extensions) {
      const results = credential.prfResults(options.extensions.prf);
      extensionResults.prf = results ? { enabled: true, results } : { enabled: true };
    }

    const style = output.style ?? 'w3c';
    const id = encodeBinary(credential.credentialId, output);
    const response: Record<string, any> = style === 'bitwarden'
      ? {
          id,
          rawId: id,
          type: 'public-key',
          extensions: extensionResults,
          response: {
            attestationObject: encodeBinary(attestationObject, output),
            clientDataJson: encodeBinary(cdj, output),
          },
        }
      : {
          id,
          rawId: id,
          type: 'public-key',
          authenticatorAttachment: 'platform',
          clientExtensionResults: extensionResults,
          response: {
            clientDataJSON: encodeBinary(cdj, output),
            attestationObject: encodeBinary(attestationObject, output),
            transports: ['internal', 'hybrid'],
          },
        };
    return { credential, response };
  }

  // navigator.credentials.get(): signs the server's challenge with `credential`
  // (or the first credential matching allowCredentials / the RP id).
  get(
    options: RequestOptionsJSON,
    output: AssertionOutputOptions,
    credential?: SoftCredential,
  ): Record<string, any> {
    const rpId = output.rpId ?? options.rpId;
    if (!rpId) throw new Error('request options carry no rpId');
    const allowed = new Set((options.allowCredentials || []).map((c) => c.id));
    const cred = credential ?? this.credentials.find((c) => c.rpId === rpId && (allowed.size === 0 || allowed.has(c.id)));
    if (!cred) throw new Error('NotAllowedError: no matching credential');

    cred.counter = output.counter ?? cred.counter + 1;
    const signCount = Buffer.alloc(4);
    signCount.writeUInt32BE(cred.counter >>> 0);
    let flags = 0;
    if (output.userPresent ?? true) flags |= FLAG_UP;
    if (output.userVerified ?? true) flags |= FLAG_UV;
    const authData = Buffer.concat([sha256(rpId), Buffer.from([flags]), signCount]);
    const cdj = clientDataJSON('webauthn.get', options.challenge, output.origin, output.clientData);
    const signature = sign('sha256', Buffer.concat([authData, sha256(cdj)]), output.signWith ?? cred.privateKey);

    const extensionResults: Record<string, unknown> = {};
    if (options.extensions && 'prf' in options.extensions) {
      const results = cred.prfResults(options.extensions.prf);
      if (results) extensionResults.prf = { results };
    }

    const style = output.style ?? 'w3c';
    const id = encodeBinary(cred.credentialId, output);
    const inner: Record<string, any> = {
      authenticatorData: encodeBinary(authData, output),
      signature: encodeBinary(signature, output),
      [style === 'bitwarden' ? 'clientDataJson' : 'clientDataJSON']: encodeBinary(cdj, output),
    };
    if (output.userHandle) inner.userHandle = encodeBinary(cred.userHandle, output);
    return style === 'bitwarden'
      ? { id, rawId: id, type: 'public-key', extensions: extensionResults, response: inner }
      : {
          id,
          rawId: id,
          type: 'public-key',
          authenticatorAttachment: 'platform',
          clientExtensionResults: extensionResults,
          response: inner,
        };
  }
}

// A fresh P-256 key, e.g. to forge a signature from an unknown key.
export function randomP256PrivateKey(): KeyObject {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
}
