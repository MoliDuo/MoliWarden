import { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { isStoredApiKeyHash } from '../utils/api-key';
import { buildAccountKeys } from '../modules/accounts/decryption';
import { buildProfileResponseWithOrgs } from '../utils/profile-response';

// CONTRACT:
// users.master_password_hash is server-side login verification only. It does
// not decrypt vault data. Password changes must keep encrypted user key material,
// securityStamp, refresh-token invalidation, and client compatibility together.
// Password hints are non-secret reminders; never treat them as recovery secrets.
function looksLikeEncString(value: string): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const payload = value.slice(firstDot + 1);
  const parts = payload.split('|');
  // Bitwarden encrypted payloads should have at least IV + ciphertext.
  return parts.length >= 2;
}

/**
 * Validate KDF parameters according to Bitwarden minimum requirements.
 * Returns an error message if invalid, or null if OK.
 */
function validateKdfParams(kdfType: number | undefined, kdfIterations: number | undefined, kdfMemory?: number | undefined, kdfParallelism?: number | undefined): string | null {
  const type = kdfType ?? 0;
  if (type !== 0 && type !== 1) {
    return 'KDF type must be PBKDF2-SHA256 or Argon2id';
  }
  if (type === 0) {
    // PBKDF2-SHA256: minimum 100 000 iterations
    if (typeof kdfIterations === 'number' && kdfIterations < 100_000) {
      return 'PBKDF2 iterations must be at least 100000';
    }
  } else if (type === 1) {
    // Argon2id: iterations >= 2, memory >= 16 MiB, parallelism >= 1
    if (typeof kdfIterations === 'number' && kdfIterations < 2) {
      return 'Argon2id iterations must be at least 2';
    }
    if (typeof kdfMemory === 'number' && kdfMemory < 16) {
      return 'Argon2id memory must be at least 16 MiB';
    }
    if (typeof kdfParallelism === 'number' && kdfParallelism < 1) {
      return 'Argon2id parallelism must be at least 1';
    }
  }
  return null;
}

function normalizeMasterPasswordHint(input: string | null | undefined): string | null {
  const normalized = String(input || '').trim();
  return normalized ? normalized : null;
}

function jwtSecretUnsafeReason(env: Env): 'missing' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

function readNestedString(source: unknown, path: string[]): string {
  let current = source;
  for (const key of path) {
    if (!current || typeof current !== 'object') return '';
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' ? current : '';
}

function readNestedNumber(source: unknown, path: string[]): number | undefined {
  let current = source;
  for (const key of path) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'number' ? current : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function masterPasswordPolicyResponse(): Record<string, unknown> {
  return {
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
    object: 'masterPasswordPolicy',
  };
}

function keysResponse(user: User): Record<string, unknown> {
  const accountKeys = buildAccountKeys(user);
  return {
    Key: user.key,
    PublicKey: user.publicKey ?? '',
    PrivateKey: user.privateKey ?? '',
    AccountKeys: accountKeys,
    Object: 'keys',
    key: user.key,
    publicKey: user.publicKey ?? '',
    privateKey: user.privateKey ?? '',
    accountKeys,
    object: 'keys',
  };
}

// POST /api/accounts/register
// - First user becomes admin.
// - Any subsequent user must provide a valid inviteCode.
export async function handleRegister(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  const unsafe = jwtSecretUnsafeReason(env);
  if (unsafe) {
    const message = unsafe === 'missing'
      ? 'JWT_SECRET is not set'
      : 'JWT_SECRET must be at least 32 characters';
    return errorResponse(message, 400);
  }

  let body: {
    email?: string;
    name?: string;
    masterPasswordHash?: string;
    key?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
    inviteCode?: string;
    masterPasswordHint?: string;
    keys?: {
      publicKey?: string;
      encryptedPrivateKey?: string;
    };
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase().trim();
  const name = body.name?.trim() || email;
  const masterPasswordHash = body.masterPasswordHash;
  const key = body.key;
  const privateKey = body.keys?.encryptedPrivateKey;
  const publicKey = body.keys?.publicKey;
  const inviteCode = (body.inviteCode || '').trim();
  const masterPasswordHint = normalizeMasterPasswordHint(body.masterPasswordHint);

  if (!email || !masterPasswordHash || !key) {
    return errorResponse('Email, masterPasswordHash, and key are required', 400);
  }
  if (!email.includes('@') || email.length < 3) {
    return errorResponse('Invalid email address', 400);
  }
  if (!privateKey || !publicKey) {
    return errorResponse('Private key and public key are required', 400);
  }
  if (!looksLikeEncString(key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (!looksLikeEncString(privateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }
  if (masterPasswordHint && masterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  const kdfErr = validateKdfParams(body.kdf, body.kdfIterations, body.kdfMemory, body.kdfParallelism);
  if (kdfErr) return errorResponse(kdfErr, 400);

  const now = new Date().toISOString();
  const auth = new AuthService(env);
  const serverHash = await auth.hashPasswordServer(masterPasswordHash, email);

  const user: User = {
    id: generateUUID(),
    email,
    name: name || email,
    masterPasswordHint,
    masterPasswordHash: serverHash,
    key,
    privateKey,
    publicKey,
    kdfType: body.kdf ?? 0,
    kdfIterations: body.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: body.kdfMemory,
    kdfParallelism: body.kdfParallelism,
    securityStamp: generateUUID(),
    role: 'user',
    status: 'active',
    verifyDevices: false, // new-device verification requires email delivery (not available)
    totpSecret: null,
    totpRecoveryCode: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    // Bitwarden creates a readable personal API key with the account. It is
    // returned only after fresh user verification and is excluded from backups.
    apiKey: randomStringAlphanum(LIMITS.auth.clientSecretLength),
    createdAt: now,
    updatedAt: now,
  };

  const userCount = await storage.getUserCount();
  if (userCount === 0) {
    user.role = 'admin';
    const created = await storage.createFirstUser(user);
    if (!created) {
      return errorResponse('Registration is temporarily unavailable, retry once', 409);
    }
    await storage.setRegistered();
    await writeAuditEvent(storage, {
      actorUserId: user.id,
      action: 'user.register.first_admin',
      targetType: 'user',
      targetId: user.id,
      category: 'security',
      level: 'security',
      metadata: { email: user.email, ...auditRequestMetadata(request) },
    });
    return jsonResponse({ success: true, role: user.role }, 200);
  }

  if (!inviteCode) {
    return errorResponse('Invite code is required', 403);
  }

  const inviteMarked = await storage.markInviteUsed(inviteCode, user.id);
  if (!inviteMarked) {
    return errorResponse('Invite code is invalid or expired', 403);
  }

  try {
    await storage.createUser(user);
  } catch (error) {
    await storage.revertInviteUsed(inviteCode, user.id);
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse('Email already registered', 409);
    }
    console.error('Registration failed after invite reservation:', error);
    throw error;
  }

  try {
    const assigned = await storage.assignInviteUsedBy(inviteCode, user.id);
    if (!assigned) {
      console.warn('Invite used_by was not assigned after registration', { inviteCode, userId: user.id });
    }
  } catch (error) {
    // The invite is already consumed. Do not reactivate it after the user row exists.
    console.error('Invite used_by assignment failed after registration:', error);
  }

  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'user.register.invite',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'info',
    metadata: { email: user.email, inviteCode, ...auditRequestMetadata(request) },
  });

  return jsonResponse({ success: true, role: user.role }, 200);
}

export function isPasswordHintEnabled(env: Env): boolean {
  return String(env.SHOW_PASSWORD_HINT || '').trim() === '1';
}

// POST /api/accounts/password-hint
export async function handleGetPasswordHint(request: Request, env: Env): Promise<Response> {
  if (!isPasswordHintEnabled(env)) {
    return errorResponse('Password hints are disabled on this server.', 400);
  }
  const storage = new StorageService(env.DB);
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = String(body.email || '').trim().toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const rateLimit = new RateLimitService(env.DB);
  const minuteBudget = await rateLimit.consumeStrictBudgetWithWindow(
    `${clientIdentifier}:password-hint`,
    LIMITS.rateLimit.passwordHintRequestsPerMinute,
    60
  );
  if (!minuteBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${minuteBudget.retryAfterSeconds || 60} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(minuteBudget.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const hourlyBudget = await rateLimit.consumeStrictBudgetWithWindow(
    `${clientIdentifier}:password-hint-hour`,
    LIMITS.rateLimit.passwordHintRequestsPerHour,
    60 * 60
  );
  if (!hourlyBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${hourlyBudget.retryAfterSeconds || 3600} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(hourlyBudget.retryAfterSeconds || 3600),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const user = await storage.getUser(email);
  const hint = user?.status === 'active' ? normalizeMasterPasswordHint(user.masterPasswordHint) : null;
  return jsonResponse({
    object: 'passwordHint',
    hasHint: !!hint,
    masterPasswordHint: hint,
  });
}

// GET /api/accounts/profile
export async function handleGetProfile(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  return jsonResponse(await buildProfileResponseWithOrgs(user, env));
}

// PUT /api/accounts/profile
export async function handleUpdateProfile(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHint?: string | null;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHint = normalizeMasterPasswordHint(body.masterPasswordHint);
  if (masterPasswordHint && masterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  user.masterPasswordHint = masterPasswordHint;
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'account.profile.update',
    category: 'security',
    level: 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedMasterPasswordHint: true,
      ...auditRequestMetadata(request),
    },
  });

  return jsonResponse(await buildProfileResponseWithOrgs(user, env));
}

// PUT/POST /api/accounts/verify-devices
// New-device verification requires an email delivery channel which MoliWarden
// does not provide. This endpoint always rejects the request so clients receive
// clear feedback that the feature is unavailable rather than silently ignoring
// the user's preference.
export async function handleSetVerifyDevices(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  // Log the attempt for audit purposes, but do not change state.
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'account.verify_devices.update.rejected',
    category: 'security',
    level: 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      reason: 'new-device verification is not supported (no email delivery channel)',
      ...auditRequestMetadata(request),
    },
  });

  return errorResponse('New device verification is not available on this server. Enable TOTP or WebAuthn two-factor authentication instead.', 400);
}

// GET /api/accounts/keys
export async function handleGetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  return jsonResponse(keysResponse(user));
}

// POST /api/accounts/keys
export async function handleSetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: {
    masterPasswordHash?: string;
    key?: string;
    encryptedPrivateKey?: string;
    publicKey?: string;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Require password verification before allowing key replacement.
  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const passwordValid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  if (body.key && !looksLikeEncString(body.key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (body.encryptedPrivateKey && !looksLikeEncString(body.encryptedPrivateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }

  const userKeyChanged = !!body.key && body.key !== user.key;
  if (body.key) user.key = body.key;
  if (body.encryptedPrivateKey) user.privateKey = body.encryptedPrivateKey;
  if (body.publicKey) user.publicKey = body.publicKey;
  user.updatedAt = new Date().toISOString();

  await storage.saveUser(user);
  // A replaced user key invalidates the recorded key id; clients backfill it again.
  if (userKeyChanged) await storage.clearUserKeyId(user.id);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'account.keys.update',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedKey: !!body.key,
      updatedPrivateKey: !!body.encryptedPrivateKey,
      updatedPublicKey: !!body.publicKey,
      ...auditRequestMetadata(request),
    },
  });

  return jsonResponse(keysResponse(user));
}

// POST/PUT /api/accounts/password
export async function handleChangePassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: {
    masterPasswordHash?: string;
    currentPasswordHash?: string;
    newMasterPasswordHash?: string;
    masterPasswordHint?: string | null;
    key?: string;
    newKey?: string;
    encryptedPrivateKey?: string;
    newEncryptedPrivateKey?: string;
    publicKey?: string;
    newPublicKey?: string;
    kdf?: number;
    kdfIterations?: number;
    kdfMemory?: number;
    kdfParallelism?: number;
    authenticationData?: Record<string, unknown>;
    unlockData?: Record<string, unknown>;
  };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = body.currentPasswordHash || body.masterPasswordHash;
  if (!currentHash) return errorResponse('Current password hash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const hasAuthenticationData = isRecord(body.authenticationData);
  const hasUnlockData = isRecord(body.unlockData);
  if (hasAuthenticationData !== hasUnlockData) {
    return errorResponse('authenticationData and unlockData must be provided together', 400);
  }

  const legacyMasterPasswordHash = typeof body.newMasterPasswordHash === 'string'
    ? body.newMasterPasswordHash.trim()
    : '';
  const legacyKey = typeof body.newKey === 'string' && body.newKey.trim()
    ? body.newKey.trim()
    : typeof body.key === 'string'
      ? body.key.trim()
      : '';
  let newMasterPasswordHash: string;
  let nextKey: string;

  if (hasAuthenticationData && hasUnlockData) {
    newMasterPasswordHash = readNestedString(body, ['authenticationData', 'masterPasswordAuthenticationHash']).trim();
    nextKey = readNestedString(body, ['unlockData', 'masterKeyWrappedUserKey']).trim();
    if (!newMasterPasswordHash || !nextKey) {
      return errorResponse('authenticationData and unlockData are incomplete', 400);
    }

    const authKdf = readNestedNumber(body, ['authenticationData', 'kdf', 'kdfType']);
    const authIterations = readNestedNumber(body, ['authenticationData', 'kdf', 'iterations']);
    const authMemory = readNestedNumber(body, ['authenticationData', 'kdf', 'memory']);
    const authParallelism = readNestedNumber(body, ['authenticationData', 'kdf', 'parallelism']);
    const unlockKdf = readNestedNumber(body, ['unlockData', 'kdf', 'kdfType']);
    const unlockIterations = readNestedNumber(body, ['unlockData', 'kdf', 'iterations']);
    const unlockMemory = readNestedNumber(body, ['unlockData', 'kdf', 'memory']);
    const unlockParallelism = readNestedNumber(body, ['unlockData', 'kdf', 'parallelism']);
    const authSalt = readNestedString(body, ['authenticationData', 'salt']);
    const unlockSalt = readNestedString(body, ['unlockData', 'salt']);
    const expectedSalt = user.email.trim().toLowerCase();

    if (authKdf === undefined || authIterations === undefined || unlockKdf === undefined || unlockIterations === undefined) {
      return errorResponse('authenticationData and unlockData must include KDF settings', 400);
    }
    if (
      authKdf !== unlockKdf ||
      authIterations !== unlockIterations ||
      authMemory !== unlockMemory ||
      authParallelism !== unlockParallelism
    ) {
      return errorResponse('authenticationData and unlockData must use the same KDF settings', 400);
    }
    if (!authSalt || authSalt !== unlockSalt || authSalt !== expectedSalt) {
      return errorResponse('Invalid master password salt', 400);
    }
    if (
      authKdf !== user.kdfType ||
      authIterations !== user.kdfIterations ||
      (authKdf === 1 && (authMemory !== user.kdfMemory || authParallelism !== user.kdfParallelism))
    ) {
      return errorResponse('KDF settings cannot be changed with the password endpoint', 400);
    }
  } else {
    if (!legacyMasterPasswordHash || !legacyKey) {
      return errorResponse('newMasterPasswordHash and key must be provided together', 400);
    }
    newMasterPasswordHash = legacyMasterPasswordHash;
    nextKey = legacyKey;
  }

  const nextPrivateKey = body.newEncryptedPrivateKey || body.encryptedPrivateKey;
  const nextPublicKey = body.newPublicKey || body.publicKey;
  if (!looksLikeEncString(nextKey)) {
    return errorResponse('new key is not a valid encrypted string', 400);
  }
  if (nextPrivateKey && !looksLikeEncString(nextPrivateKey)) {
    return errorResponse('new encryptedPrivateKey is not a valid encrypted string', 400);
  }

  if (
    (typeof body.kdf === 'number' && body.kdf !== user.kdfType) ||
    (typeof body.kdfIterations === 'number' && body.kdfIterations !== user.kdfIterations) ||
    (typeof body.kdfMemory === 'number' && body.kdfMemory !== user.kdfMemory) ||
    (typeof body.kdfParallelism === 'number' && body.kdfParallelism !== user.kdfParallelism)
  ) {
    return errorResponse('KDF settings cannot be changed with the password endpoint', 400);
  }
  const shouldUpdateHint = typeof body.masterPasswordHint === 'string' || body.masterPasswordHint === null;
  const nextMasterPasswordHint = shouldUpdateHint ? normalizeMasterPasswordHint(body.masterPasswordHint) : undefined;
  if (nextMasterPasswordHint && nextMasterPasswordHint.length > 120) {
    return errorResponse('masterPasswordHint must be 120 characters or fewer', 400);
  }

  user.masterPasswordHash = await auth.hashPasswordServer(newMasterPasswordHash, user.email);
  user.key = nextKey;
  if (nextPrivateKey) user.privateKey = nextPrivateKey;
  if (nextPublicKey) user.publicKey = nextPublicKey;
  if (shouldUpdateHint) {
    user.masterPasswordHint = nextMasterPasswordHint ?? null;
  }
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  await storage.deleteRefreshTokensByUserId(user.id);
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: 'user.password.change',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'security',
    metadata: { email: user.email, ...auditRequestMetadata(request) },
  });

  return new Response(null, { status: 200 });
}

// GET /api/accounts/totp
export async function handleGetRevisionDate(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const revisionDate = await storage.getRevisionDate(userId);

  // Return as milliseconds timestamp (Bitwarden format)
  const timestamp = new Date(revisionDate).getTime();
  return jsonResponse(timestamp);
}

// POST /api/accounts/verify-password
export async function handleVerifyPassword(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  let body: { masterPasswordHash?: string; authenticationData?: Record<string, unknown> };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const masterPasswordHash =
    body.masterPasswordHash ||
    readNestedString(body, ['authenticationData', 'masterPasswordAuthenticationHash']);
  if (!masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }

  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }

  return jsonResponse(masterPasswordPolicyResponse());
}

// POST /api/accounts/key-management/user-key-id
// Current official clients (SDK "user key id backfill") report the id of the
// user key once after unlock and fail login/unlock if the call is rejected by a
// 404. The id is non-secret metadata; like Vaultwarden it can be set only once.
export async function handleSetUserKeyId(request: Request, env: Env, userId: string): Promise<Response> {
  let body: { userKeyId?: unknown; UserKeyId?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const keyId = body?.userKeyId ?? body?.UserKeyId;
  if (typeof keyId !== 'string' || !/^[A-Za-z0-9+/=_-]{1,128}$/.test(keyId)) {
    return errorResponse('userKeyId is invalid', 400);
  }
  const storage = new StorageService(env.DB);
  if (!(await storage.setUserKeyIdIfUnset(userId, keyId))) {
    return errorResponse('User key id is already set', 422);
  }
  return new Response(null, { status: 200 });
}

// POST /api/accounts/api-key
export async function handleGetApiKey(request: Request, env: Env, userId: string): Promise<Response> {
  return apiKey(request, env, userId, false);
}

// POST /api/accounts/rotate-api-key
export async function handleRotateApiKey(request: Request, env: Env, userId: string): Promise<Response> {
  return apiKey(request, env, userId, true);
}

async function apiKey(request: Request, env: Env, userId: string, rotate: boolean): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let body: Record<string, string | undefined>;
  try {
    const contentType = request.headers.get('content-type') || '';
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const currentHash = String(body.masterPasswordHash || body.master_password_hash || body.password || '').trim();
  if (!currentHash) return errorResponse('masterPasswordHash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!rotate && isStoredApiKeyHash(user.apiKey)) {
    return errorResponse(
      'This API key was created by an older server version and cannot be displayed. Rotate it once to use the Bitwarden-compatible readable format.',
      409
    );
  }

  let auditAction = 'account.api_key.view';
  if (rotate || !user.apiKey) {
    user.apiKey = randomStringAlphanum(LIMITS.auth.clientSecretLength);
    user.updatedAt = new Date().toISOString();
    await storage.saveUser(user);
    auditAction = rotate ? 'account.api_key.rotate' : 'account.api_key.create';
  }
  await writeAuditEvent(storage, {
    actorUserId: user.id,
    action: auditAction,
    category: 'security',
    level: rotate ? 'security' : 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse({
    apiKey: user.apiKey,
    revisionDate: user.updatedAt,
    object: 'apiKey',
  });
}

// Generate a random alphanumeric string of the given length using crypto.getRandomValues.
function randomStringAlphanum(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const maxUnbiased = Math.floor(256 / chars.length) * chars.length;
  const bytes = new Uint8Array(Math.max(16, length));

  while (result.length < length) {
    crypto.getRandomValues(bytes);
    for (const value of bytes) {
      if (value >= maxUnbiased) continue;
      result += chars[value % chars.length];
      if (result.length >= length) break;
    }
  }

  return result;
}
