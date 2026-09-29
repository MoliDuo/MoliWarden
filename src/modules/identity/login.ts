import { LIMITS } from '../../config/limits';
import { IdentityError, invalidGrant } from '../../http/errors';
import type { Deps } from '../../main/deps';
import type { Device, User, WebAuthnPrfDecryptionOption } from '../../types';
import { buildAccountKeys, buildUserDecryptionOptions } from '../accounts/decryption';
import { recordAudit, requestMetadata } from '../audit/service';
import { signAccessToken } from '../auth/access-token';
import { lockedFor, minutes, recordFailure } from '../auth/lockout';
import { startSession, type ClientType } from '../auth/sessions';
import { saveDevice, setDevicePushToken } from '../devices/repo';
import { masterPasswordPolicy } from '../two-factor/login';
import type { TokenForm } from './schemas';
import { isWebSession } from './web-session';

// What every successful grant ends with: a device record, a session and
// the token response official clients expect.

export interface SigningInDevice {
  identifier: string | null;
  name: string;
  type: number;
  pushToken: string | null;
}

const UNKNOWN_DEVICE_TYPE = 14;

// Clients name the device in the form or in headers.
export function signingInDevice(form: TokenForm, request: Request): SigningInDevice {
  const identifier = (form.deviceIdentifier || form.device_identifier || request.headers.get('X-Device-Identifier') || '').trim();
  const name = (form.deviceName || form.device_name || request.headers.get('X-Device-Name') || '').trim();
  const type = Number.parseInt(form.deviceType || form.device_type || request.headers.get('Device-Type') || '', 10);
  return {
    identifier: identifier.slice(0, 128) || null,
    name: name.slice(0, 128) || 'Unknown device',
    type: Number.isFinite(type) && type >= 0 ? type : UNKNOWN_DEVICE_TYPE,
    pushToken: (form.devicePushToken || form.device_push_token).trim() || null,
  };
}

// Decides how long the session may sit unused.
export function clientTypeOf(request: Request, clientId: string): ClientType {
  if (isWebSession(request)) return 'web';
  const id = clientId.trim().toLowerCase();
  return id === 'mobile' || id === 'browser' || id === 'desktop' || id === 'cli' ? id : 'other';
}

// --- Guessing ---------------------------------------------------------------

export async function assertNotLockedOut(deps: Deps, key: string): Promise<void> {
  const locked = await lockedFor(deps.limiter, key);
  if (locked !== null) throw lockedOut(`Too many failed login attempts. Try again in ${minutes(locked)} minutes.`);
}

// Counts a failed attempt and ends the request with `error`, or with the
// lockout it caused.
export async function failAttempt(deps: Deps, key: string, error: IdentityError): Promise<never> {
  const locked = await recordFailure(deps.limiter, key);
  if (locked !== null) throw lockedOut(`Too many failed login attempts. Account locked for ${minutes(locked)} minutes.`);
  throw error;
}

const lockedOut = (message: string) => new IdentityError('TooManyRequests', message, 429);

export const accountDisabled = () => invalidGrant('Account is disabled');

export function auditLoginFailure(deps: Deps, request: Request, user: User, action: string, grantType: string, device: SigningInDevice) {
  return recordAudit(deps.db, {
    actorUserId: user.id,
    action,
    category: 'auth',
    level: 'warn',
    targetType: 'user',
    targetId: user.id,
    metadata: { grantType, deviceIdentifier: device.identifier, ...requestMetadata(request) },
  });
}

// --- Tokens -----------------------------------------------------------------

export interface Tokens {
  body: Record<string, unknown>;
  refreshToken: string;
}

export interface TokenExtras {
  // Lets this device skip two-step login next time.
  rememberToken?: string | null;
  // The vault key, when an approved device request supplied it.
  key?: string;
  // Unlocks the vault with the passkey that signed in.
  prfOption?: WebAuthnPrfDecryptionOption | null;
  userVerificationToken?: string;
}

export function tokenBody(deps: Deps, user: User, device: Device | null, extras: TokenExtras = {}): Record<string, unknown> {
  const accountKeys = buildAccountKeys(user);
  const decryptionOptions = buildUserDecryptionOptions(user, extras.prfOption ?? null);
  return {
    access_token: signAccessToken(deps.tokens, user, device),
    expires_in: LIMITS.auth.accessTokenTtlSeconds,
    token_type: 'Bearer',
    ...(extras.rememberToken ? { TwoFactorToken: extras.rememberToken } : {}),
    Key: extras.key ?? user.key,
    PrivateKey: user.privateKey,
    AccountKeys: accountKeys,
    accountKeys,
    Kdf: user.kdfType,
    KdfIterations: user.kdfIterations,
    KdfMemory: user.kdfMemory,
    KdfParallelism: user.kdfParallelism,
    ForcePasswordReset: false,
    ResetMasterPassword: false,
    MasterPasswordPolicy: masterPasswordPolicy(),
    ApiUseKeyConnector: false,
    scope: 'api offline_access',
    unofficialServer: true,
    ...(extras.userVerificationToken
      ? { UserVerificationToken: extras.userVerificationToken, userVerificationToken: extras.userVerificationToken }
      : {}),
    UserDecryptionOptions: decryptionOptions,
    userDecryptionOptions: decryptionOptions,
  };
}

// Mobile apps send their push token with the login; the relay needs it
// to wake them up for sync. Registering again on every login lets a failed
// registration heal.
async function savePushToken(deps: Deps, user: User, device: Device, pushToken: string): Promise<void> {
  const saved = await setDevicePushToken(deps.db, user.id, device.deviceIdentifier, pushToken);
  if (saved) deps.push.register({ userId: user.id, identifier: saved.deviceIdentifier, type: saved.type, pushUuid: saved.pushUuid, pushToken });
}

export interface Login {
  user: User;
  grantType: string;
  device: SigningInDevice;
  clientType: ClientType;
  auditAction?: string;
  auditTarget?: { type: string; id: string };
  extras?: TokenExtras;
}

// Signs the user in once every check has passed.
export async function issueLogin(deps: Deps, request: Request, login: Login): Promise<Tokens> {
  const { user, device: signingIn } = login;
  const device = signingIn.identifier
    ? await saveDevice(deps.db, user.id, { identifier: signingIn.identifier, name: signingIn.name, type: signingIn.type })
    : null;
  if (device && signingIn.pushToken) await savePushToken(deps, user, device, signingIn.pushToken);

  const refreshToken = await startSession(deps.db, user, device, login.clientType);
  await recordAudit(deps.db, {
    actorUserId: user.id,
    action: login.auditAction ?? 'auth.login.success',
    category: 'auth',
    targetType: login.auditTarget?.type ?? 'user',
    targetId: login.auditTarget?.id ?? user.id,
    metadata: {
      grantType: login.grantType,
      webSession: isWebSession(request),
      deviceIdentifier: signingIn.identifier,
      deviceType: signingIn.type,
      ...requestMetadata(request),
    },
  });
  return { body: tokenBody(deps, user, device, login.extras), refreshToken };
}
