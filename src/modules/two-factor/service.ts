import { randomUUID } from 'node:crypto';
import { badRequest, forbidden, HttpError } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Db, Executor } from '../../platform/db';
import { consumeOnce } from '../../platform/db/consumed';
import { withLease } from '../../platform/db/lease';
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
import type { Passkey } from '../passkeys/repo';
import { createRecoveryCode, recoveryCodeMatches } from './recovery-code';
import {
  deleteProviders,
  deleteRememberTokens,
  findProviders,
  findYubicoCredentials,
  saveProvider,
  saveYubicoCredentials,
  TOTP,
  YUBIKEY,
  type YubiKeyData,
} from './repo';
import { isTotpSecret, normalizeTotpSecret, randomTotpSecret, stepExpiry, totpStep } from './totp';
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
  yubiKey: YubiKeyData | null;
  // The public ids of the registered YubiKeys.
  yubiKeys: string[];
  securityKeys: Passkey[];
}

export async function factorsOf(db: Executor, user: User): Promise<Factors> {
  const [{ totp, yubiKey }, securityKeys] = await Promise.all([findProviders(db, user.id), listSecurityKeys(db, user.id)]);
  return {
    totpSecret: totp?.secret ?? null,
    yubiKey,
    yubiKeys: (yubiKey?.keys ?? []).filter((key): key is string => !!key),
    securityKeys,
  };
}

export const hasSecondFactor = (factors: Factors) =>
  !!factors.totpSecret || factors.yubiKeys.length > 0 || factors.securityKeys.length > 0;

export { usersWithSecondFactor } from './repo';

async function requirePassword(user: User, secret: string | null | undefined): Promise<void> {
  if (!(await verifyMasterPassword(user, secret))) throw badRequest('User verification failed.');
}

// Turning a factor on also makes sure a recovery code exists, and signs out
// every other session so it has to pass the new factor.
async function afterFactorChange(deps: Deps, user: User): Promise<void> {
  await ensureRecoveryCode(deps.db, user);
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

async function ensureRecoveryCode(db: Executor, user: User): Promise<string> {
  if (!user.recoveryCode) {
    user.recoveryCode = createRecoveryCode();
    await updateUser(db, user.id, { recoveryCode: user.recoveryCode });
  }
  return user.recoveryCode;
}

// Counts a TOTP code once: codes are valid for about a minute and a copy
// must not work a second time.
export async function useTotpCode(db: Executor, userId: string, secret: string, code: string): Promise<boolean> {
  const step = totpStep(secret, code);
  return step !== null && (await consumeOnce(db, `totp:${userId}:${step}`, stepExpiry(step)));
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
  if (type === Provider.WebAuthn) await deleteAllSecurityKeys(deps.db, user.id);
  else await deleteProviders(deps.db, user.id, type === Provider.Authenticator ? TOTP : YUBIKEY);
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
  const { totp } = await findProviders(deps.db, user.id);
  const key = totp?.secret ?? randomTotpSecret();
  return authenticatorJson(!!totp, key, signUserVerification(deps.tokens, user, 'totp.setup', key));
}

async function enableTotp(deps: Deps, request: Request, user: User, secret: string, code: string, invalidCode: string) {
  if (!isTotpSecret(secret)) throw badRequest('Invalid TOTP secret');
  if (!(await useTotpCode(deps.db, user.id, secret, code))) throw badRequest(invalidCode);
  await saveProvider(deps.db, user.id, TOTP, { secret });
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
    return { enabled: true, recoveryCode: user.recoveryCode, object: 'twoFactor' };
  }
  if (input.enabled === false) {
    if (!input.masterPasswordHash) throw badRequest('masterPasswordHash is required to disable TOTP');
    if (!(await verifyMasterPassword(user, input.masterPasswordHash))) throw badRequest('Invalid password');
    await deleteProviders(deps.db, user.id, TOTP);
    await endAllSessions(deps.db, user.id);
    await audit(deps, request, user, 'account.totp.disable');
    return { enabled: false, object: 'twoFactor' };
  }
  throw badRequest('enabled must be true or false');
}

// --- YubiKey -----------------------------------------------------------------

export async function isTotpEnabled(deps: Deps, user: User): Promise<boolean> {
  return !!(await findProviders(deps.db, user.id)).totp;
}

export async function yubiKeySettings(deps: Deps, user: User) {
  const [credentials, { yubiKey }] = await Promise.all([findYubicoCredentials(deps.db), findProviders(deps.db, user.id)]);
  const canManage = user.role === 'admin' && user.status === 'active';
  const slot = (index: number) => yubiKey?.keys[index] ?? null;
  return {
    Enabled: !!yubiKey?.keys.some(Boolean),
    Key1: slot(0),
    Key2: slot(1),
    Key3: slot(2),
    Key4: slot(3),
    Key5: slot(4),
    Nfc: yubiKey?.nfc ?? false,
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

const BOOTSTRAP_LEASE_MS = 2 * 60_000;

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
  const leased = await withLease(db, 'yubico.bootstrap', BOOTSTRAP_LEASE_MS, async () => {
    const concurrent = await findYubicoCredentials(db);
    if (concurrent) return { credentials: concurrent, created: false };
    const issued = await requestYubicoCredentials(email, otp);
    if (!issued) return null;
    await saveYubicoCredentials(db, issued);
    return { credentials: issued, created: true };
  });
  if (leased) return leased.value;
  // Someone else is getting them right now.
  const concurrent = await findYubicoCredentials(db);
  return concurrent ? { credentials: concurrent, created: false } : null;
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

  await saveProvider(deps.db, user.id, YUBIKEY, { keys: publicIds.slice(0, 5), nfc: input.nfc });
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
  const code = await ensureRecoveryCode(deps.db, user);
  return { Code: code, code, Object: 'twoFactorRecover', object: 'twoFactorRecover' };
}

// Turns every second factor off and signs the user out everywhere: the
// recovery code is spent, and a new one replaces it.
export async function resetTwoFactor(deps: Deps, user: User): Promise<string> {
  const changes = { recoveryCode: createRecoveryCode(), securityStamp: randomUUID() };
  await deps.db.transaction().execute(async (tx) => {
    await updateUser(tx, user.id, changes);
    await deleteProviders(tx, user.id);
    await deleteAllSecurityKeys(tx, user.id);
    await deleteRememberTokens(tx, user.id);
    await endAllSessions(tx, user.id);
  });
  // The caller may go on to sign the user in with the new stamp.
  Object.assign(user, changes);
  return changes.recoveryCode;
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
    recoveryCodeMatches(input.recoveryCode, user.recoveryCode);
  if (!valid) {
    await recordFailure(deps.limiter, lockKey);
    throw badRequest('Invalid credentials or recovery code');
  }
  const newRecoveryCode = await resetTwoFactor(deps, user);
  await clearFailures(deps.limiter, lockKey);
  await audit(deps, request, user, 'account.totp.recover');
  return { success: true, twoFactorEnabled: false, newRecoveryCode, object: 'twoFactorRecovery' };
}
