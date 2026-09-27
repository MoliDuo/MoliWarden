// Real Bitwarden client crypto for tests that talk to official clients.
//
// Accounts and organizations created here are byte-for-byte what the official
// clients would produce, so the official CLI can log in, unlock and decrypt
// them. The fake-crypto helpers in helpers.ts cannot be used for that.
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  createPublicKey,
  createPrivateKey,
} from 'node:crypto';

// Minimum the server accepts is 100 000; official clients default to 600 000.
export const DEFAULT_KDF_ITERATIONS = Number(process.env.BW_TEST_KDF_ITERATIONS || 600_000);

export interface SymmetricKey {
  enc: Buffer;
  mac: Buffer;
}

export function splitKey(key64: Buffer): SymmetricKey {
  if (key64.length !== 64) throw new Error(`expected a 64-byte key, got ${key64.length}`);
  return { enc: key64.subarray(0, 32), mac: key64.subarray(32, 64) };
}

function hkdfExpand(prk: Buffer, info: string, length: number): Buffer {
  const out: Buffer[] = [];
  let previous = Buffer.alloc(0);
  for (let i = 1; Buffer.concat(out).length < length; i++) {
    previous = createHmac('sha256', prk).update(Buffer.concat([previous, Buffer.from(info), Buffer.from([i])])).digest();
    out.push(previous);
  }
  return Buffer.concat(out).subarray(0, length);
}

// EncString type 2: AES-256-CBC + HMAC-SHA256.
export function encryptBytes(data: Buffer | Uint8Array, key: SymmetricKey): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key.enc, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const mac = createHmac('sha256', key.mac).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString('base64')}|${ct.toString('base64')}|${mac.toString('base64')}`;
}

export function encryptString(text: string, key: SymmetricKey): string {
  return encryptBytes(Buffer.from(text, 'utf8'), key);
}

export function decryptBytes(encString: string, key: SymmetricKey): Buffer {
  const dot = encString.indexOf('.');
  if (encString.slice(0, dot) !== '2') throw new Error(`unsupported EncString type in ${encString.slice(0, 8)}`);
  const [ivB64, ctB64, macB64] = encString.slice(dot + 1).split('|');
  const iv = Buffer.from(ivB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');
  const expected = createHmac('sha256', key.mac).update(Buffer.concat([iv, ct])).digest();
  if (!timingSafeEqual(expected, Buffer.from(macB64, 'base64'))) throw new Error('EncString MAC mismatch');
  const decipher = createDecipheriv('aes-256-cbc', key.enc, iv);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export function decryptString(encString: string, key: SymmetricKey): string {
  return decryptBytes(encString, key).toString('utf8');
}

// EncString type 4: RSA-2048-OAEP-SHA1, as used for org key wrapping.
export function rsaEncrypt(data: Buffer, publicKeyB64: string): string {
  const key = createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
  const ct = publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, data);
  return `4.${ct.toString('base64')}`;
}

export function rsaDecrypt(encString: string, pkcs8: Buffer): Buffer {
  const dot = encString.indexOf('.');
  const type = Number(encString.slice(0, dot));
  if (type !== 4 && type !== 3) throw new Error(`unsupported RSA EncString type ${type}`);
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const payload = Buffer.from(encString.slice(dot + 1).split('|')[0], 'base64');
  return privateDecrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: type === 3 ? 'sha256' : 'sha1' }, payload);
}

export function generateRsaKeyPair(): { publicKeyB64: string; pkcs8: Buffer } {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  return {
    publicKeyB64: pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    pkcs8: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
  };
}

export interface MasterKeyMaterial {
  masterKey: Buffer;
  masterPasswordHash: string;
  stretched: SymmetricKey;
}

export function deriveMasterKey(email: string, password: string, iterations = DEFAULT_KDF_ITERATIONS): MasterKeyMaterial {
  const masterKey = pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from(email.trim().toLowerCase(), 'utf8'), iterations, 32, 'sha256');
  const masterPasswordHash = pbkdf2Sync(masterKey, Buffer.from(password, 'utf8'), 1, 32, 'sha256').toString('base64');
  return {
    masterKey,
    masterPasswordHash,
    stretched: { enc: hkdfExpand(masterKey, 'enc', 32), mac: hkdfExpand(masterKey, 'mac', 32) },
  };
}

export interface RealAccount {
  email: string;
  password: string;
  kdfIterations: number;
  masterPasswordHash: string;
  userKey: SymmetricKey;
  publicKeyB64: string;
  privateKeyPkcs8: Buffer;
  // Registration payload (minus inviteCode) as official clients send it.
  registerBody: Record<string, unknown>;
}

export function createAccountMaterial(email: string, password: string, iterations = DEFAULT_KDF_ITERATIONS): RealAccount {
  const { masterPasswordHash, stretched } = deriveMasterKey(email, password, iterations);
  const userKeyBytes = randomBytes(64);
  const userKey = splitKey(userKeyBytes);
  const rsa = generateRsaKeyPair();
  return {
    email,
    password,
    kdfIterations: iterations,
    masterPasswordHash,
    userKey,
    publicKeyB64: rsa.publicKeyB64,
    privateKeyPkcs8: rsa.pkcs8,
    registerBody: {
      email,
      name: email.split('@')[0],
      masterPasswordHash,
      masterPasswordHint: null,
      key: encryptBytes(userKeyBytes, stretched),
      keys: { publicKey: rsa.publicKeyB64, encryptedPrivateKey: encryptBytes(rsa.pkcs8, userKey) },
      kdf: 0,
      kdfIterations: iterations,
    },
  };
}

export interface RealOrganization {
  orgKey: SymmetricKey;
  createBody: Record<string, unknown>;
}

// Mirrors the official "create organization" request for the free plan.
export function createOrganizationMaterial(name: string, billingEmail: string, owner: RealAccount, collectionName = 'Default collection'): RealOrganization {
  const orgKeyBytes = randomBytes(64);
  const orgKey = splitKey(orgKeyBytes);
  const rsa = generateRsaKeyPair();
  return {
    orgKey,
    createBody: {
      name,
      billingEmail,
      planType: 0,
      key: rsaEncrypt(orgKeyBytes, owner.publicKeyB64),
      keys: { publicKey: rsa.publicKeyB64, encryptedPrivateKey: encryptBytes(rsa.pkcs8, orgKey) },
      collectionName: encryptString(collectionName, orgKey),
    },
  };
}

// Unwraps the org key a member received (profile.organizations[].key).
export function unwrapOrgKey(wrapped: string, account: RealAccount): SymmetricKey {
  return splitKey(rsaDecrypt(wrapped, account.privateKeyPkcs8));
}

export function randomPassword(): string {
  return `Pw-${randomUUID()}`;
}
