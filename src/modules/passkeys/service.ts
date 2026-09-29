import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { randomUUID } from 'node:crypto';
import { badRequest, conflict, notFound } from '../../http/errors';
import type { Deps } from '../../main/deps';
import { base64url, sha256 } from '../../platform/crypto';
import type { Executor } from '../../platform/db';
import type { AccountPasskeyChallengeScope, User } from '../../types';
import { findUserById } from '../accounts/repo';
import { recordAudit, requestMetadata } from '../audit/service';
import { verifyMasterPassword } from '../auth/password';
import {
  consumeChallenge,
  deletePasskey,
  deletePasskeys,
  findPasskeyByCredentialId,
  insertPasskey,
  listPasskeys,
  saveChallenge,
  setPasskeySlot,
  updatePasskeyCounter,
  updatePasskeyKeys,
  type Passkey,
} from './repo';
import {
  challengeOf,
  descriptorOf,
  prfStatus,
  relyingParty,
  toAuthenticationResponse,
  toRegistrationResponse,
  toVerifiable,
  userHandleFor,
  userIdFromHandle,
} from './webauthn';

// Login passkeys (passwordless sign-in, optionally unlocking the vault
// through PRF) and security keys for two-step login share the WebAuthn
// machinery here. The two kinds are never interchangeable.

const MAX_PER_PURPOSE = 5;
const TIMEOUT_MS = 60_000;

// Login passkey ceremonies hand the client a signed token naming the
// challenge; two-step ceremonies find the challenge in the response.
interface ChallengeClaims {
  scope: AccountPasskeyChallengeScope;
  challenge: string;
  uid: string | null;
  rpId: string;
}

const ttlSeconds = (scope: AccountPasskeyChallengeScope) =>
  scope === 'CreateCredential' || scope === 'TwoFactorCreate' ? 7 * 60 : 17 * 60;

const challengeHash = (challenge: string) => base64url(sha256(challenge));

// The key set the client wraps with the passkey's PRF output.
export interface PrfKeySet {
  encryptedUserKey: string;
  encryptedPublicKey: string;
  encryptedPrivateKey: string;
}

export class PasskeyRejected extends Error {}

async function remember(db: Executor, scope: AccountPasskeyChallengeScope, challenge: string, userId: string | null): Promise<void> {
  const now = Date.now();
  await saveChallenge(db, challengeHash(challenge), scope, userId, now + ttlSeconds(scope) * 1000, now);
}

function signChallenge(deps: Deps, claims: ChallengeClaims): string {
  return deps.tokens.sign('passkey-challenge', claims, ttlSeconds(claims.scope));
}

function readChallenge(deps: Deps, token: string, scope: AccountPasskeyChallengeScope): ChallengeClaims | null {
  const claims = deps.tokens.verify<ChallengeClaims>('passkey-challenge', token);
  return claims?.scope === scope ? claims : null;
}

async function consume(db: Executor, challenge: string, scope: AccountPasskeyChallengeScope, userId: string | null): Promise<void> {
  if (!(await consumeChallenge(db, challengeHash(challenge), scope, userId, Date.now()))) {
    throw new PasskeyRejected('Passkey challenge has expired or was already used');
  }
}

// --- Passwordless login ---------------------------------------------------

export async function loginAssertionOptions(deps: Deps, request: Request) {
  const { rpId } = relyingParty(deps.config, request);
  const options = await generateAuthenticationOptions({ rpID: rpId, allowCredentials: [], userVerification: 'required', timeout: TIMEOUT_MS });
  await remember(deps.db, 'Authentication', options.challenge, null);
  return { options, token: signChallenge(deps, { scope: 'Authentication', challenge: options.challenge, uid: null, rpId }) };
}

// Verifies a login passkey assertion; `scope` UpdateKeySet proves possession
// of one of `userId`'s passkeys before changing its keys.
export async function verifyLoginAssertion(
  deps: Deps,
  request: Request,
  input: { token: string; deviceResponse: unknown; scope: 'Authentication' | 'UpdateKeySet'; userId?: string },
): Promise<{ user: User; passkey: Passkey }> {
  const claims = readChallenge(deps, input.token, input.scope);
  if (!claims) throw new PasskeyRejected('Passkey challenge token is invalid or expired');
  if (input.userId !== undefined && claims.uid !== input.userId) throw new PasskeyRejected('Passkey challenge is for another user');
  const response = toAuthenticationResponse(input.deviceResponse);
  if (!response) throw new PasskeyRejected('Invalid passkey assertion response');
  await consume(deps.db, claims.challenge, input.scope, claims.uid);

  const passkey = await findPasskeyByCredentialId(deps.db, response.rawId);
  if (!passkey || passkey.purpose !== 'login') throw new PasskeyRejected('Passkey is not registered for login');
  const userId = claims.uid ?? userIdFromHandle(response.response.userHandle) ?? passkey.userId;
  if (userId !== passkey.userId) throw new PasskeyRejected('Passkey does not belong to this user');
  const user = await findUserById(deps.db, userId);
  if (!user) throw new PasskeyRejected('Passkey user is not available');

  const { origins } = relyingParty(deps.config, request);
  const counter = await verifyAssertion({
    response,
    expectedChallenge: claims.challenge,
    expectedOrigin: origins,
    expectedRPID: claims.rpId,
    credential: toVerifiable(passkey),
    requireUserVerification: true,
  });
  if (counter === null) throw new PasskeyRejected('Passkey assertion could not be verified');
  await updatePasskeyCounter(deps.db, passkey.id, counter, new Date().toISOString());
  return { user, passkey: { ...passkey, counter } };
}

// --- Managing login passkeys ----------------------------------------------

const masterPasswordFailed = () => badRequest('Master password verification failed');

function auditPasskey(deps: Deps, request: Request, userId: string, action: string, passkey: Passkey | string) {
  return recordAudit(deps.db, {
    actorUserId: userId,
    action,
    category: 'security',
    targetType: 'accountPasskey',
    targetId: typeof passkey === 'string' ? passkey : passkey.id,
    metadata: { ...(typeof passkey === 'string' ? {} : { prfStatus: prfStatus(passkey) }), ...requestMetadata(request) },
  });
}

export function listLoginPasskeys(db: Executor, userId: string): Promise<Passkey[]> {
  return listPasskeys(db, userId, 'login');
}

export async function loginPasskeyCreationOptions(deps: Deps, request: Request, user: User, secret: string | null) {
  if (!(await verifyMasterPassword(user, secret))) throw masterPasswordFailed();
  const existing = await listPasskeys(deps.db, user.id, 'login');
  if (existing.length >= MAX_PER_PURPOSE) throw badRequest('Maximum passkey count reached');
  const { rpId, rpName } = relyingParty(deps.config, request);
  const options = await generateRegistrationOptions({
    rpID: rpId,
    rpName,
    userID: userHandleFor(user.id),
    userName: user.email,
    userDisplayName: user.name || user.email,
    attestationType: 'none',
    timeout: TIMEOUT_MS,
    excludeCredentials: existing.map(descriptorOf),
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    // Asks the authenticator for PRF support, which lets the passkey unlock the vault.
    extensions: { prf: {} } as PublicKeyCredentialCreationOptionsJSON['extensions'],
  });
  await remember(deps.db, 'CreateCredential', options.challenge, user.id);
  return { options, token: signChallenge(deps, { scope: 'CreateCredential', challenge: options.challenge, uid: user.id, rpId }) };
}

export async function createLoginPasskey(
  deps: Deps,
  request: Request,
  userId: string,
  input: { token: string; deviceResponse: unknown; name: string; supportsPrf: boolean; keys: PrfKeySet | null },
): Promise<Passkey> {
  const claims = readChallenge(deps, input.token, 'CreateCredential');
  if (!claims || claims.uid !== userId) throw badRequest('Passkey challenge token is invalid or expired');
  await consumeOrReject(deps.db, claims.challenge, 'CreateCredential', userId);
  if ((await listPasskeys(deps.db, userId, 'login')).length >= MAX_PER_PURPOSE) throw badRequest('Maximum passkey count reached');

  const registered = await verifyRegistration(deps, request, input.deviceResponse, claims.challenge, claims.rpId, true);
  const now = new Date().toISOString();
  const passkey: Passkey = {
    ...registered,
    id: randomUUID(),
    userId,
    purpose: 'login',
    name: input.name.trim().slice(0, 128) || 'Account passkey',
    encryptedUserKey: input.keys?.encryptedUserKey ?? null,
    encryptedPublicKey: input.keys?.encryptedPublicKey ?? null,
    encryptedPrivateKey: input.keys?.encryptedPrivateKey ?? null,
    supportsPrf: input.supportsPrf || input.keys !== null,
    slot: null,
    createdAt: now,
    updatedAt: now,
  };
  await insertPasskey(deps.db, passkey);
  await auditPasskey(deps, request, userId, 'account.passkey.create', passkey);
  return passkey;
}

export async function keySetUpdateOptions(deps: Deps, request: Request, user: User, input: { secret: string | null; passkeyId: string | null }) {
  if (!(await verifyMasterPassword(user, input.secret))) throw masterPasswordFailed();
  let passkeys = await listPasskeys(deps.db, user.id, 'login');
  if (input.passkeyId) passkeys = passkeys.filter((passkey) => passkey.id === input.passkeyId);
  if (!passkeys.length) throw notFound(input.passkeyId ? 'Account passkey not found' : 'No account passkeys registered');
  const { rpId } = relyingParty(deps.config, request);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: passkeys.map(descriptorOf),
    userVerification: 'required',
    timeout: TIMEOUT_MS,
  });
  await remember(deps.db, 'UpdateKeySet', options.challenge, user.id);
  return { options, token: signChallenge(deps, { scope: 'UpdateKeySet', challenge: options.challenge, uid: user.id, rpId }) };
}

// Stores the keys a passkey's PRF output wraps, proven by an assertion
// with that passkey.
export async function updateLoginPasskeyKeys(
  deps: Deps,
  request: Request,
  userId: string,
  input: { token: string; deviceResponse: unknown; keys: PrfKeySet },
): Promise<void> {
  let passkey: Passkey;
  try {
    ({ passkey } = await verifyLoginAssertion(deps, request, { ...input, scope: 'UpdateKeySet', userId }));
  } catch (error) {
    if (error instanceof PasskeyRejected) throw badRequest(error.message);
    throw error;
  }
  await updatePasskeyKeys(deps.db, passkey.id, input.keys, new Date().toISOString());
  await auditPasskey(deps, request, userId, 'account.passkey.encryption.enable', passkey.id);
}

export async function deleteLoginPasskey(deps: Deps, request: Request, user: User, input: { secret: string | null; id: string }) {
  if (!(await verifyMasterPassword(user, input.secret))) throw masterPasswordFailed();
  if (!(await deletePasskey(deps.db, user.id, 'login', input.id))) throw notFound('Passkey not found');
  await auditPasskey(deps, request, user.id, 'account.passkey.delete', input.id);
}

// --- Security keys for two-step login -------------------------------------

// The user's security keys, each with its KeyN slot (1-5). Keys stored
// without one (restored from a backup) take the lowest free slots.
export async function listSecurityKeys(db: Executor, userId: string): Promise<Passkey[]> {
  const keys = await listPasskeys(db, userId, 'twoFactor');
  const taken = new Set(keys.map((key) => key.slot));
  for (const key of keys) {
    if (key.slot !== null) continue;
    key.slot = freeSlot(taken);
    taken.add(key.slot);
    await setPasskeySlot(db, key.id, key.slot);
  }
  return keys.sort((a, b) => a.slot! - b.slot!);
}

function freeSlot(taken: Set<number | null>): number {
  let slot = 1;
  while (taken.has(slot)) slot += 1;
  return slot;
}

export async function securityKeyCreationOptions(
  deps: Deps,
  request: Request,
  user: User,
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const existing = await listPasskeys(deps.db, user.id, 'twoFactor');
  if (existing.length >= MAX_PER_PURPOSE) throw badRequest('Maximum WebAuthn credential count reached.');
  const { rpId, rpName } = relyingParty(deps.config, request);
  const options = await generateRegistrationOptions({
    rpID: rpId,
    rpName,
    userID: userHandleFor(user.id),
    userName: user.email,
    userDisplayName: user.name || user.email,
    attestationType: 'none',
    timeout: TIMEOUT_MS,
    excludeCredentials: existing.map(descriptorOf),
    // A security key without a PIN is fine for a second factor.
    authenticatorSelection: { residentKey: 'discouraged', requireResidentKey: false, userVerification: 'discouraged' },
  });
  await remember(deps.db, 'TwoFactorCreate', options.challenge, user.id);
  return options;
}

export async function addSecurityKey(
  deps: Deps,
  request: Request,
  userId: string,
  input: { deviceResponse: unknown; name: string | null },
): Promise<void> {
  const existing = await listSecurityKeys(deps.db, userId);
  if (existing.length >= MAX_PER_PURPOSE) throw badRequest('Maximum WebAuthn credential count reached.');
  const response = toRegistrationResponse(input.deviceResponse);
  const challenge = response && challengeOf(response);
  if (!challenge) throw badRequest('Invalid passkey registration response');
  await consumeOrReject(deps.db, challenge, 'TwoFactorCreate', userId);

  const { rpId } = relyingParty(deps.config, request);
  const registered = await verifyRegistration(deps, request, input.deviceResponse, challenge, rpId, false);
  const now = new Date().toISOString();
  await insertPasskey(deps.db, {
    ...registered,
    id: randomUUID(),
    userId,
    purpose: 'twoFactor',
    name: input.name || `Passkey ${existing.length + 1}`,
    encryptedUserKey: null,
    encryptedPublicKey: null,
    encryptedPrivateKey: null,
    supportsPrf: false,
    slot: freeSlot(new Set(existing.map((key) => key.slot))),
    createdAt: now,
    updatedAt: now,
  });
}

// Options for the second step of a login, or null without security keys.
export async function securityKeyAssertionOptions(
  deps: Deps,
  request: Request,
  keys: Passkey[],
): Promise<PublicKeyCredentialRequestOptionsJSON | null> {
  if (!keys.length) return null;
  const { rpId } = relyingParty(deps.config, request);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: keys.map(descriptorOf),
    userVerification: 'discouraged',
    timeout: TIMEOUT_MS,
  });
  await remember(deps.db, 'TwoFactorAuthentication', options.challenge, keys[0].userId);
  return options;
}

export async function verifySecurityKeyAssertion(deps: Deps, request: Request, userId: string, deviceResponse: unknown): Promise<boolean> {
  const response = toAuthenticationResponse(deviceResponse);
  const challenge = response && challengeOf(response);
  if (!response || !challenge) return false;
  const key = await findPasskeyByCredentialId(deps.db, response.rawId);
  if (!key || key.userId !== userId || key.purpose !== 'twoFactor') return false;
  if (!(await consumeChallenge(deps.db, challengeHash(challenge), 'TwoFactorAuthentication', userId, Date.now()))) return false;

  const { origins, rpId } = relyingParty(deps.config, request);
  const counter = await verifyAssertion({
    response,
    expectedChallenge: challenge,
    expectedOrigin: origins,
    expectedRPID: rpId,
    credential: toVerifiable(key),
    requireUserVerification: false,
  });
  if (counter === null) return false;
  await updatePasskeyCounter(deps.db, key.id, counter, new Date().toISOString());
  return true;
}

export async function deleteSecurityKey(db: Executor, userId: string, slot: number): Promise<void> {
  const keys = await listSecurityKeys(db, userId);
  const key = keys.find((candidate) => candidate.slot === slot);
  // The last key goes only with the provider (/two-factor/disable).
  if (!key || keys.length < 2) throw badRequest('Unable to delete WebAuthn credential.');
  await deletePasskey(db, userId, 'twoFactor', key.id);
}

export function deleteAllSecurityKeys(db: Executor, userId: string): Promise<void> {
  return deletePasskeys(db, userId, 'twoFactor');
}

// --- Shared ----------------------------------------------------------------

// The authenticator's new signature counter, or null if the assertion
// does not verify.
async function verifyAssertion(options: Parameters<typeof verifyAuthenticationResponse>[0]): Promise<number | null> {
  try {
    const { verified, authenticationInfo } = await verifyAuthenticationResponse(options);
    if (!verified || (options.requireUserVerification && !authenticationInfo.userVerified)) return null;
    return authenticationInfo.newCounter;
  } catch {
    return null;
  }
}

async function consumeOrReject(db: Executor, challenge: string, scope: AccountPasskeyChallengeScope, userId: string): Promise<void> {
  try {
    await consume(db, challenge, scope, userId);
  } catch (error) {
    if (error instanceof PasskeyRejected) throw badRequest(error.message);
    throw error;
  }
}

type Registered = Pick<Passkey, 'publicKey' | 'credentialId' | 'counter' | 'type' | 'aaGuid' | 'transports'>;

async function verifyRegistration(
  deps: Deps,
  request: Request,
  deviceResponse: unknown,
  challenge: string,
  rpId: string,
  requireUserVerification: boolean,
): Promise<Registered> {
  const response = toRegistrationResponse(deviceResponse);
  if (!response) throw badRequest('Invalid passkey registration response');
  const { origins } = relyingParty(deps.config, request);
  let result: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      requireUserPresence: true,
      requireUserVerification,
    });
  } catch {
    throw badRequest('Passkey registration could not be verified');
  }
  if (!result.verified) throw badRequest('Passkey registration could not be verified');
  const { credential, credentialType, aaguid } = result.registrationInfo;
  if (await findPasskeyByCredentialId(deps.db, credential.id)) throw conflict('Passkey is already registered');
  const transports = response.response.transports?.map(String).filter(Boolean).slice(0, 12);
  return {
    publicKey: base64url(credential.publicKey),
    credentialId: credential.id,
    counter: credential.counter,
    type: credentialType || 'public-key',
    aaGuid: aaguid || null,
    transports: transports?.length ? transports : null,
  };
}
