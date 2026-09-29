import { randomUUID } from 'node:crypto';
import { LIMITS } from '../../config/limits';
import { badRequest, conflict, forbidden, HttpError } from '../../http/errors';
import { consume } from '../../http/rate-limit';
import type { Deps } from '../../main/deps';
import { randomAlphanumeric } from '../../platform/crypto';
import { isEncString } from '../../platform/enc-string';
import type { User } from '../../types';
import { recordAudit, requestMetadata } from '../audit/service';
import { openApiKey, sealApiKey } from '../auth/api-key';
import { hashMasterPassword, requireMasterPassword } from '../auth/password';
import { endAllSessions } from '../auth/sessions';
import { profileOrganizations } from '../organizations/service';
import { masterPasswordPolicy } from '../two-factor/login';
import { factorsOf, hasSecondFactor } from '../two-factor/service';
import { buildAccountKeys } from './decryption';
import { profileJson } from './profile';
import {
  claimUserKeyId,
  countUsers,
  findRevisionDate,
  findUserByEmail,
  insertUser,
  isInviteActive,
  lockRegistrations,
  updateUser,
  useInvite,
} from './repo';
import type { PasswordInput, RegisterInput } from './schemas';

// The account itself: registration, profile, master password, account keys
// and the personal API key.
//
// The server never sees the master password. Clients send a hash of it,
// which the server hashes again to check sign-ins; it decrypts nothing. The
// user key comes wrapped by the master key, so a password change must
// replace the hash, the wrapped key and the security stamp together.

const PBKDF2 = 0;
const ARGON2ID = 1;

function kdfProblem(input: Pick<RegisterInput, 'kdf' | 'kdfIterations' | 'kdfMemory' | 'kdfParallelism'>): string | null {
  const { kdf, kdfIterations: iterations, kdfMemory: memory, kdfParallelism: parallelism } = input;
  if (kdf === PBKDF2) return iterations != null && iterations < 100_000 ? 'PBKDF2 iterations must be at least 100000' : null;
  if (kdf !== ARGON2ID) return 'KDF type must be PBKDF2-SHA256 or Argon2id';
  if (iterations != null && iterations < 2) return 'Argon2id iterations must be at least 2';
  if (memory != null && memory < 16) return 'Argon2id memory must be at least 16 MiB';
  if (parallelism != null && parallelism < 1) return 'Argon2id parallelism must be at least 1';
  return null;
}

function audit(deps: Deps, request: Request, user: User, action: string, level: 'info' | 'security' = 'security', metadata = {}) {
  return recordAudit(deps.db, {
    actorUserId: user.id,
    action,
    category: 'security',
    level,
    targetType: 'user',
    targetId: user.id,
    metadata: { ...metadata, ...requestMetadata(request) },
  });
}

// The first account becomes the admin; everyone after needs an invite.
export async function register(deps: Deps, request: Request, input: RegisterInput) {
  const problem = kdfProblem(input);
  if (problem) throw badRequest(problem);

  const now = new Date().toISOString();
  const id = randomUUID();
  const user: User = {
    id,
    email: input.email,
    name: input.name ?? input.email,
    masterPasswordHint: input.masterPasswordHint,
    masterPasswordHash: await hashMasterPassword(input.masterPasswordHash, input.email),
    key: input.key,
    privateKey: input.keys.encryptedPrivateKey,
    publicKey: input.keys.publicKey,
    kdfType: input.kdf,
    kdfIterations: input.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: input.kdfMemory ?? undefined,
    kdfParallelism: input.kdfParallelism ?? undefined,
    securityStamp: randomUUID(),
    role: 'user',
    status: 'active',
    recoveryCode: null,
    // Like upstream, every account starts with a personal API key.
    apiKey: sealApiKey(deps.secrets, id, randomAlphanumeric(LIMITS.auth.clientSecretLength)),
    createdAt: now,
    updatedAt: now,
  };

  const invalidInvite = () => forbidden('Invite code is invalid or expired');
  await deps.db.transaction().execute(async (tx) => {
    await lockRegistrations(tx);
    const first = (await countUsers(tx)) === 0;
    // The invite is checked first, so only invitees learn whether an email is taken.
    if (!first && !input.inviteCode) throw forbidden('Invite code is required');
    if (!first && !(await isInviteActive(tx, input.inviteCode))) throw invalidInvite();
    if (await findUserByEmail(tx, user.email)) throw conflict('Email already registered');
    if (first) user.role = 'admin';
    await insertUser(tx, user);
    // Marked after the insert, as the invite records who used it.
    if (!first && !(await useInvite(tx, input.inviteCode, user.id))) throw invalidInvite();
  });

  const first = user.role === 'admin';
  await audit(deps, request, user, first ? 'user.register.first_admin' : 'user.register.invite', first ? 'security' : 'info', {
    email: user.email,
  });
  return { success: true, role: user.role };
}

// Off unless the operator enables it: a hint tells anyone who knows the
// email something about the password.
export async function passwordHint(deps: Deps, address: string, email: string) {
  if (!deps.config.showPasswordHint) throw badRequest('Password hints are disabled on this server.');
  if (!email) throw badRequest('Email is required');
  await consume(deps.limiter, 'password-hint', address);
  await consume(deps.limiter, 'password-hint-hourly', address);
  const user = await findUserByEmail(deps.db, email);
  const hint = user?.status === 'active' ? user.masterPasswordHint : null;
  return { hasHint: !!hint, masterPasswordHint: hint, object: 'passwordHint' };
}

export async function profile(deps: Deps, user: User) {
  const [organizations, factors] = await Promise.all([
    profileOrganizations(deps.db, user.id),
    factorsOf(deps.db, user),
  ]);
  return profileJson(user, {
    organizations,
    twoFactorEnabled: hasSecondFactor(factors),
    yubikeyEnabled: factors.yubiKeys.length > 0,
  });
}

export async function updateProfile(
  deps: Deps,
  request: Request,
  user: User,
  input: { name?: string; masterPasswordHint?: string | null },
) {
  const changes = {
    ...(input.name ? { name: input.name } : {}),
    ...(input.masterPasswordHint !== undefined ? { masterPasswordHint: input.masterPasswordHint } : {}),
  };
  user.updatedAt = await updateUser(deps.db, user.id, changes);
  Object.assign(user, changes);
  await audit(deps, request, user, 'account.profile.update', 'info');
  return profile(deps, user);
}

export function keysJson(user: User) {
  const accountKeys = buildAccountKeys(user);
  return {
    key: user.key,
    publicKey: user.publicKey ?? '',
    privateKey: user.privateKey ?? '',
    accountKeys,
    object: 'keys',
    Key: user.key,
    PublicKey: user.publicKey ?? '',
    PrivateKey: user.privateKey ?? '',
    AccountKeys: accountKeys,
    Object: 'keys',
  };
}

export async function setKeys(
  deps: Deps,
  request: Request,
  user: User,
  input: { masterPasswordHash: string; key?: string; encryptedPrivateKey?: string; publicKey?: string },
) {
  await requireMasterPassword(user, input.masterPasswordHash);
  const changes = {
    ...(input.key ? { key: input.key } : {}),
    ...(input.encryptedPrivateKey ? { privateKey: input.encryptedPrivateKey } : {}),
    ...(input.publicKey ? { publicKey: input.publicKey } : {}),
    // The id clients reported belongs to the replaced user key; they report the new one.
    ...(input.key && input.key !== user.key ? { keyId: null } : {}),
  };
  user.updatedAt = await updateUser(deps.db, user.id, changes);
  Object.assign(user, changes);
  await audit(deps, request, user, 'account.keys.update');
  return keysJson(user);
}

// The new hash and wrapped user key. KDF changes have an endpoint of their
// own, which this server does not offer, so the settings must stay as they are.
function newCredentials(user: User, input: PasswordInput): { hash: string; key: string } {
  const { authenticationData: auth, unlockData: unlock } = input;
  if (!auth !== !unlock) throw badRequest('authenticationData and unlockData must be provided together');
  if (!auth || !unlock) {
    if (!input.newMasterPasswordHash || !input.key) throw badRequest('newMasterPasswordHash and key must be provided together');
    if (!isEncString(input.key)) throw badRequest('key: Must be an encrypted string.');
    return { hash: input.newMasterPasswordHash, key: input.key };
  }

  const same = (a: typeof auth.kdf, b: typeof auth.kdf) =>
    a.kdfType === b.kdfType && a.iterations === b.iterations && a.memory === b.memory && a.parallelism === b.parallelism;
  if (!same(auth.kdf, unlock.kdf)) throw badRequest('authenticationData and unlockData must use the same KDF settings');
  const salt = user.email.toLowerCase();
  if (auth.salt !== salt || unlock.salt !== salt) throw badRequest('Invalid master password salt');
  const unchanged =
    auth.kdf.kdfType === user.kdfType &&
    auth.kdf.iterations === user.kdfIterations &&
    (user.kdfType !== ARGON2ID ||
      (auth.kdf.memory === (user.kdfMemory ?? null) && auth.kdf.parallelism === (user.kdfParallelism ?? null)));
  if (!unchanged) throw badRequest('KDF settings cannot be changed with the password endpoint');
  return { hash: auth.masterPasswordAuthenticationHash, key: unlock.masterKeyWrappedUserKey };
}

// Signs the user out everywhere: every session was opened with the old password.
export async function changePassword(deps: Deps, request: Request, user: User, input: PasswordInput): Promise<void> {
  await requireMasterPassword(user, input.masterPasswordHash);
  const next = newCredentials(user, input);
  const masterPasswordHash = await hashMasterPassword(next.hash, user.email);
  await deps.db.transaction().execute(async (tx) => {
    await updateUser(tx, user.id, {
      masterPasswordHash,
      key: next.key,
      securityStamp: randomUUID(),
      ...(input.masterPasswordHint !== undefined ? { masterPasswordHint: input.masterPasswordHint } : {}),
    });
    await endAllSessions(tx, user.id);
  });
  await audit(deps, request, user, 'user.password.change', 'security', { email: user.email });
}

export async function verifyPassword(user: User, secret: string) {
  await requireMasterPassword(user, secret);
  return masterPasswordPolicy();
}

// Current clients report the id of the user key once after unlocking and
// fail if the call is refused. It is not secret and can be set only once.
export async function setUserKeyId(deps: Deps, user: User, keyId: string): Promise<void> {
  if (!(await claimUserKeyId(deps.db, user.id, keyId))) throw new HttpError(422, 'User key id is already set');
}

// The personal API key is shown only after the master password is confirmed.
export async function apiKey(deps: Deps, request: Request, user: User, secret: string, rotate: boolean) {
  await requireMasterPassword(user, secret);
  let action = 'account.api_key.view';
  let key = user.apiKey && !rotate ? openApiKey(deps.secrets, user.id, user.apiKey) : null;
  if (!key) {
    action = rotate ? 'account.api_key.rotate' : 'account.api_key.create';
    key = randomAlphanumeric(LIMITS.auth.clientSecretLength);
    user.apiKey = sealApiKey(deps.secrets, user.id, key);
    user.updatedAt = await updateUser(deps.db, user.id, { apiKey: user.apiKey });
  }
  await audit(deps, request, user, action, rotate ? 'security' : 'info');
  return { apiKey: key, revisionDate: user.updatedAt, object: 'apiKey' };
}

// Milliseconds since the epoch, as Bitwarden sends it.
export async function revisionDate(deps: Deps, user: User): Promise<number> {
  return new Date((await findRevisionDate(deps.db, user.id)) ?? user.updatedAt).getTime();
}
