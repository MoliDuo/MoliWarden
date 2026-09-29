import { randomUUID } from 'node:crypto';
import { badRequest, forbidden, HttpError } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Db, Executor } from '../../platform/db';
import type { User } from '../../types';
import { findUserByEmail, updateUser } from '../accounts/repo';
import { requestMetadata, recordAudit } from '../audit/service';
import { clearFailures, lockedFor, minutes, recordFailure } from '../auth/lockout';
import { verifyMasterPassword } from '../auth/password';
import { endAllSessions } from '../auth/sessions';
import { signUserVerification, verifyUserVerification } from '../auth/user-verification';
import {
  addSecurityKey,
  deleteAllSecurityKeys,
  deleteSecurityKey,
  listSecurityKeys,
  securityKeyCreationOptions,
} from '../passkeys/service';
import { usersWithPasskeys, type Passkey } from '../passkeys/repo';
import { createRecoveryCode, recoveryCodeMatches } from './recovery-code';
import {
  claimYubicoBootstrap,
  deleteRememberTokens,
  findYubicoCredentials,
  releaseYubicoBootstrap,
  saveYubicoCredentials,
  useTotpStep,
} from './repo';
import { isTotpSecret, normalizeTotpSecret, randomTotpSecret, totpStep } from './totp';
import {
  isYubiKeyOtp,
  requestYubicoCredentials,
  validationUrls,
  verifyYubiKeyOtp,
  yubiKeyPublicId,
  type YubicoCredentials,
} from './yubico';

// Two-step login settings: an authenticator app (TOTP), YubiKey OTPs and
// security keys (WebAuthn), plus the recovery code that turns them all off.
// Email codes need a mail service and are not offered.

export const Provider = {
  Authenticator: 0,
  YubiKey: 3,
  Remember: 5,
  WebAuthn: 7,
  RecoveryCode: 8,
} as const;

type ManagedProvider = typeof Provider.Authenticator | typeof Provider.YubiKey | typeof Provider.WebAuthn;

// The second factors a user has set up.
export interface Factors {
  totpSecret: string | null;
  yubiKeys: string[];
  securityKeys: Passkey[];
}

export const yubiKeysOf = (user: User): string[] =>
  [user.yubikeyKey1, user.yubikeyKey2, user.yubikeyKey3, user.yubikeyKey4, user.yubikeyKey5]
    .map((key) => key?.trim().toLowerCase() ?? '')
    .filter(Boolean);

export async function factorsOf(db: Executor, user: User): Promise<Factors> {
  return {
    totpSecret: isTotpSecret(user.totpSecret) ? normalizeTotpSecret(user.totpSecret) : null,
    yubiKeys: yubiKeysOf(user),
    securityKeys: await listSecurityKeys(db, user.id),
  };
}

export const hasSecondFactor = (factors: Factors) =>
  !!factors.totpSecret || factors.yubiKeys.length > 0 || factors.securityKeys.length > 0;

// Which of the users have a second factor, in one query.
export async function usersWithSecondFactor(db: Executor, users: User[]): Promise<Set<string>> {
  const keyHolders = await usersWithPasskeys(
    db,
    users.map((user) => user.id),
    'twoFactor',
  );
  const enabled = (user: User) => isTotpSecret(user.totpSecret) || yubiKeysOf(user).length > 0 || keyHolders.has(user.id);
  return new Set(users.filter(enabled).map((user) => user.id));
}

async function requirePassword(user: User, secret: string | null | undefined): Promise<void> {
  if (!(await verifyMasterPassword(user, secret))) throw badRequest('User verification failed.');
}

// Turning a factor on also makes sure a recovery code exists, and signs out
// every other session so it has to pass the new factor.
async function afterFactorChange(deps: Deps, user: User): Promise<void> {
  if (!user.totpRecoveryCode) {
    user.totpRecoveryCode = createRecoveryCode();
    await updateUser(deps.db, user.id, { totpRecoveryCode: user.totpRecoveryCode });
  }
  await endAllSessions(deps.db, user.id);
}

function audit(deps: Deps, request: Request, user: User, action: string, target: { type?: string; id?: string | null } = {}) {
  return recordAudit(deps.db, {
    actorUserId: user.id,
    action,
    category: 'security',
    level: 'security',
    targetType: target.type ?? 'user',
    targetId: target.id === undefined ? user.id : target.id,
    metadata: requestMetadata(request),
  });
}

// Counts a TOTP code once: codes are valid for about a minute and a copy
// must not work a second time.
async function useTotpCode(db: Executor, userId: string, secret: string, code: string): Promise<boolean> {
  const step = totpStep(secret, code);
  return step !== null && (await useTotpStep(db, userId, step, Date.now()));
}

// --- Overview ----------------------------------------------------------------

export function providerJson(type: number, enabled: boolean) {
  return { Enabled: enabled, Type: type, Object: 'twoFactorProvider' };
}

export async function listProviders(deps: Deps, user: User) {
  const factors = await factorsOf(deps.db, user);
  const data = [];
  if (factors.totpSecret) data.push(providerJson(Provider.Authenticator, true));
  if (factors.yubiKeys.length) data.push(providerJson(Provider.YubiKey, true));
  if (factors.securityKeys.length) data.push(providerJson(Provider.WebAuthn, true));
  return { Data: data, ContinuationToken: null, Object: 'list' };
}

export async function disableProvider(deps: Deps, request: Request, user: User, type: number, secret: string | null) {
  if (type !== Provider.Authenticator && type !== Provider.YubiKey && type !== Provider.WebAuthn) {
    throw badRequest('Two-factor provider is not supported by this server.');
  }
  await requirePassword(user, secret);
  const actions: Record<ManagedProvider, string> = {
    [Provider.Authenticator]: 'account.totp.disable',
    [Provider.YubiKey]: 'account.yubikey.disable',
    [Provider.WebAuthn]: 'account.webauthn_2fa.disable',
  };
  if (type === Provider.Authenticator) await updateUser(deps.db, user.id, { totpSecret: null });
  else if (type === Provider.YubiKey) await updateUser(deps.db, user.id, { yubikeys: [], yubikeyNfc: false });
  else await deleteAllSecurityKeys(deps.db, user.id);
  await endAllSessions(deps.db, user.id);
  await audit(deps, request, user, actions[type]);
  return providerJson(type, false);
}

// --- Authenticator app -------------------------------------------------------

function authenticatorJson(enabled: boolean, key: string, userVerificationToken: string | null = null) {
  return { Enabled: enabled, Key: key, UserVerificationToken: userVerificationToken, Object: 'twoFactorAuthenticator' };
}

// The key to scan, with a token that lets the user enable it without typing
// the master password again.
export async function authenticatorSetup(deps: Deps, user: User, secret: string | null) {
  await requirePassword(user, secret);
  const key = normalizeTotpSecret(user.totpSecret) || randomTotpSecret();
  return authenticatorJson(!!user.totpSecret, key, signUserVerification(deps.tokens, user, 'totp.setup', key));
}

async function enableTotp(deps: Deps, request: Request, user: User, secret: string, code: string, invalidCode: string) {
  if (!isTotpSecret(secret)) throw badRequest('Invalid TOTP secret');
  if (!(await useTotpCode(deps.db, user.id, secret, code))) throw badRequest(invalidCode);
  await updateUser(deps.db, user.id, { totpSecret: secret });
  await afterFactorChange(deps, user);
  await audit(deps, request, user, 'account.totp.enable');
}

export async function enableAuthenticator(
  deps: Deps,
  request: Request,
  user: User,
  input: { key: string; token: string; userVerificationToken: string },
) {
  const key = normalizeTotpSecret(input.key);
  if (!key || !input.token.trim() || !input.userVerificationToken) {
    throw badRequest('Key, token and userVerificationToken are required');
  }
  if (!verifyUserVerification(deps.tokens, input.userVerificationToken, user, 'totp.setup', key)) {
    throw badRequest('User verification failed.');
  }
  await enableTotp(deps, request, user, key, input.token, 'Invalid token.');
  return authenticatorJson(true, key);
}

// The web vault's own endpoint (/api/accounts/totp).
export async function setTotp(
  deps: Deps,
  request: Request,
  user: User,
  input: { enabled?: boolean; secret?: string; token?: string; masterPasswordHash?: string; userVerificationToken?: string },
) {
  if (input.enabled === true) {
    const secret = normalizeTotpSecret(input.secret);
    if (!isTotpSecret(secret)) throw badRequest('Invalid TOTP secret');
    if (!input.token) throw badRequest('TOTP token is required');
    const verified =
      verifyUserVerification(deps.tokens, input.userVerificationToken, user, 'totp.setup', secret) ||
      (await verifyMasterPassword(user, input.masterPasswordHash));
    if (!verified) throw badRequest('User verification failed.');
    await enableTotp(deps, request, user, secret, input.token, 'Invalid TOTP token');
    return { enabled: true, recoveryCode: user.totpRecoveryCode, object: 'twoFactor' };
  }
  if (input.enabled === false) {
    if (!input.masterPasswordHash) throw badRequest('masterPasswordHash is required to disable TOTP');
    if (!(await verifyMasterPassword(user, input.masterPasswordHash))) throw badRequest('Invalid password');
    await updateUser(deps.db, user.id, { totpSecret: null });
    await endAllSessions(deps.db, user.id);
    await audit(deps, request, user, 'account.totp.disable');
    return { enabled: false, object: 'twoFactor' };
  }
  throw badRequest('enabled must be true or false');
}

// --- YubiKey -----------------------------------------------------------------

export async function yubiKeySettings(deps: Deps, user: User) {
  const credentials = await findYubicoCredentials(deps.db);
  const canManage = user.role === 'admin' && user.status === 'active';
  return {
    Enabled: yubiKeysOf(user).length > 0,
    Key1: user.yubikeyKey1,
    Key2: user.yubikeyKey2,
    Key3: user.yubikeyKey3,
    Key4: user.yubikeyKey4,
    Key5: user.yubikeyKey5,
    Nfc: user.yubikeyNfc,
    Object: 'twoFactorYubiKey',
    YubicoConfigured: !!credentials,
    YubicoCanManage: canManage,
    ...(canManage ? { YubicoClientId: credentials?.clientId ?? '', YubicoSecretKey: credentials?.secretKey ?? '' } : {}),
  };
}

export async function readYubiKeySettings(deps: Deps, user: User, secret: string | null) {
  await requirePassword(user, secret);
  return yubiKeySettings(deps, user);
}

const BOOTSTRAP_CLAIM_MS = 2 * 60_000;

// Validating OTPs needs Yubico API credentials. Without any, the first OTP
// a user presents gets the server its own. `created` tells that this OTP
// was spent on that and cannot be validated again.
async function yubicoCredentialsFor(
  db: Db,
  email: string,
  otp: string,
): Promise<{ credentials: YubicoCredentials; created: boolean } | null> {
  const existing = await findYubicoCredentials(db);
  if (existing) return { credentials: existing, created: false };
  const claim = await claimYubicoBootstrap(db, Date.now(), BOOTSTRAP_CLAIM_MS);
  if (!claim) {
    const concurrent = await findYubicoCredentials(db);
    return concurrent ? { credentials: concurrent, created: false } : null;
  }
  try {
    const issued = await requestYubicoCredentials(email, otp);
    if (!issued) return null;
    const concurrent = await findYubicoCredentials(db);
    if (concurrent) return { credentials: concurrent, created: false };
    await saveYubicoCredentials(db, issued);
    return { credentials: issued, created: true };
  } finally {
    await releaseYubicoBootstrap(db, claim).catch(() => undefined);
  }
}

export async function checkYubiKeyOtp(deps: Deps, email: string, otp: string): Promise<boolean> {
  const found = await yubicoCredentialsFor(deps.db, email, otp);
  if (!found) return false;
  return found.created || verifyYubiKeyOtp(validationUrls(deps.config.yubicoValidationUrls), found.credentials, otp);
}

// Each of the five slots takes an OTP typed by the key, or the public id of
// a key already registered.
export async function enableYubiKeys(
  deps: Deps,
  request: Request,
  user: User,
  input: { secret: string | null; keys: string[]; nfc: boolean },
) {
  await requirePassword(user, input.secret);
  const publicIds: (string | null)[] = [];
  for (const raw of input.keys) {
    const value = raw.trim();
    if (!value) {
      publicIds.push(null);
      continue;
    }
    const publicId = yubiKeyPublicId(value);
    if (!publicId) throw badRequest('Invalid YubiKey OTP.');
    if (isYubiKeyOtp(value) && !(await checkYubiKeyOtp(deps, user.email, value))) {
      throw badRequest('Invalid YubiKey OTP.');
    }
    publicIds.push(publicId);
  }
  if (!publicIds.some(Boolean)) throw badRequest('At least one YubiKey OTP is required.');

  Object.assign(user, {
    yubikeyKey1: publicIds[0] ?? null,
    yubikeyKey2: publicIds[1] ?? null,
    yubikeyKey3: publicIds[2] ?? null,
    yubikeyKey4: publicIds[3] ?? null,
    yubikeyKey5: publicIds[4] ?? null,
    yubikeyNfc: input.nfc,
  });
  await updateUser(deps.db, user.id, { yubikeys: publicIds, yubikeyNfc: input.nfc });
  await afterFactorChange(deps, user);
  await audit(deps, request, user, 'account.yubikey.enable');
  return yubiKeySettings(deps, user);
}

// Admins may set the server's Yubico credentials directly.
export async function configureYubico(
  deps: Deps,
  request: Request,
  user: User,
  input: { secret: string | null; clientId: string; secretKey: string },
) {
  if (user.role !== 'admin') throw forbidden();
  await requirePassword(user, input.secret);
  if (!input.clientId || !input.secretKey) throw badRequest('Yubico Client ID and Secret Key are required.');
  await saveYubicoCredentials(deps.db, { clientId: input.clientId, secretKey: input.secretKey });
  await audit(deps, request, user, 'system.yubico.credentials.update', { type: 'system', id: 'yubico' });
  return yubiKeySettings(deps, user);
}

// Gets the server Yubico credentials with the user's YubiKey. Anyone may
// do this once; only admins may replace existing credentials.
export async function bootstrapYubico(deps: Deps, request: Request, user: User, input: { secret: string | null; otp: string }) {
  await requirePassword(user, input.secret);
  if (!yubiKeyPublicId(input.otp)) throw badRequest('Invalid YubiKey OTP.');
  const unable = () => badRequest('Unable to initialize Yubico validation credentials.');
  const alreadyConfigured = () => forbidden('Yubico validation credentials are already configured.');

  if (user.role === 'admin') {
    const issued = await requestYubicoCredentials(user.email, input.otp);
    if (!issued) throw unable();
    await saveYubicoCredentials(deps.db, issued);
  } else {
    if (await findYubicoCredentials(deps.db)) throw alreadyConfigured();
    const found = await yubicoCredentialsFor(deps.db, user.email, input.otp);
    if (!found) throw unable();
    if (!found.created) throw alreadyConfigured();
  }
  const action = user.role === 'admin' ? 'system.yubico.credentials.reconfigure' : 'system.yubico.credentials.initialize';
  await audit(deps, request, user, action, { type: 'system', id: 'yubico' });
  return yubiKeySettings(deps, user);
}

// --- Security keys (WebAuthn) ------------------------------------------------

function securityKeysJson(keys: Passkey[]) {
  const list = keys.map((key) => ({ Id: key.slot, id: key.slot, Name: key.name, name: key.name, Migrated: false, migrated: false }));
  return { Enabled: keys.length > 0, enabled: keys.length > 0, Keys: list, keys: list, Object: 'twoFactorWebAuthn', object: 'twoFactorWebAuthn' };
}

export async function readSecurityKeys(deps: Deps, user: User, secret: string | null) {
  await requirePassword(user, secret);
  return securityKeysJson(await listSecurityKeys(deps.db, user.id));
}

export async function securityKeyChallenge(deps: Deps, request: Request, user: User, secret: string | null) {
  await requirePassword(user, secret);
  return securityKeyCreationOptions(deps, request, user);
}

export async function registerSecurityKey(
  deps: Deps,
  request: Request,
  user: User,
  input: { secret: string | null; deviceResponse: unknown; name: string | null },
) {
  await requirePassword(user, input.secret);
  await addSecurityKey(deps, request, user.id, { deviceResponse: input.deviceResponse, name: input.name });
  await afterFactorChange(deps, user);
  await audit(deps, request, user, 'account.webauthn_2fa.enable', { type: 'accountPasskey', id: null });
  return securityKeysJson(await listSecurityKeys(deps.db, user.id));
}

export async function removeSecurityKey(deps: Deps, request: Request, user: User, input: { secret: string | null; id: number }) {
  await requirePassword(user, input.secret);
  if (!Number.isInteger(input.id) || input.id <= 0) throw badRequest('Invalid key id');
  await deleteSecurityKey(deps.db, user.id, input.id);
  await endAllSessions(deps.db, user.id);
  await audit(deps, request, user, 'account.webauthn_2fa.delete', { type: 'accountPasskey', id: String(input.id) });
  return securityKeysJson(await listSecurityKeys(deps.db, user.id));
}

// --- Recovery ----------------------------------------------------------------

export async function revealRecoveryCode(deps: Deps, user: User, masterPasswordHash: string | null) {
  if (!masterPasswordHash) throw badRequest('masterPasswordHash is required');
  if (!(await verifyMasterPassword(user, masterPasswordHash))) throw badRequest('Invalid password');
  if (!user.totpRecoveryCode) {
    user.totpRecoveryCode = createRecoveryCode();
    await updateUser(deps.db, user.id, { totpRecoveryCode: user.totpRecoveryCode });
  }
  const code = user.totpRecoveryCode;
  return { Code: code, code, Object: 'twoFactorRecover', object: 'twoFactorRecover' };
}

// Turns every second factor off and signs the user out everywhere: the
// recovery code is spent, and a new one replaces it.
export async function resetTwoFactor(deps: Deps, user: User): Promise<string> {
  const changes = {
    totpSecret: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    totpRecoveryCode: createRecoveryCode(),
    securityStamp: randomUUID(),
  };
  await deps.db.transaction().execute(async (tx) => {
    await updateUser(tx, user.id, { ...changes, yubikeys: [] });
    await deleteAllSecurityKeys(tx, user.id);
    await deleteRememberTokens(tx, user.id);
    await endAllSessions(tx, user.id);
  });
  // The caller may go on to sign the user in with the new stamp.
  Object.assign(user, changes);
  return changes.totpRecoveryCode;
}

export async function recoverWithCode(
  deps: Deps,
  request: Request,
  address: string,
  input: { email: string; masterPasswordHash: string; recoveryCode: string },
) {
  const lockKey = `${address}:recover-2fa`;
  const locked = await lockedFor(deps.limiter, lockKey);
  if (locked !== null) {
    throw new HttpError(429, `Too many failed recovery attempts. Try again in ${minutes(locked)} minutes.`);
  }
  if (!input.email || !input.masterPasswordHash || !input.recoveryCode) {
    throw badRequest('Email, masterPasswordHash and recoveryCode are required');
  }
  const user = await findUserByEmail(deps.db, input.email);
  const valid =
    !!user &&
    user.status === 'active' &&
    (await verifyMasterPassword(user, input.masterPasswordHash)) &&
    recoveryCodeMatches(input.recoveryCode, user.totpRecoveryCode);
  if (!valid) {
    await recordFailure(deps.limiter, lockKey);
    throw badRequest('Invalid credentials or recovery code');
  }
  const newRecoveryCode = await resetTwoFactor(deps, user);
  await clearFailures(deps.limiter, lockKey);
  await audit(deps, request, user, 'account.totp.recover');
  return { success: true, twoFactorEnabled: false, newRecoveryCode, object: 'twoFactorRecovery' };
}
