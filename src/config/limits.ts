// Protocol constants and fixed limits. Rate limit budgets are in
// src/http/rate-limit.ts, deployment settings in src/main/config.ts.
export const LIMITS = {
  auth: {
    accessTokenTtlSeconds: 7200,
    // Refresh tokens expire after this long unused, per client type...
    refreshTokenWebSlidingTtlMs: 30 * 24 * 60 * 60 * 1000,
    refreshTokenDefaultSlidingTtlMs: 30 * 24 * 60 * 60 * 1000,
    refreshTokenMobileSlidingTtlMs: 90 * 24 * 60 * 60 * 1000,
    // ...and after this long in any case.
    refreshTokenAbsoluteTtlMs: 365 * 24 * 60 * 60 * 1000,
    refreshTokenRandomBytes: 32,
    // JWT_SECRET and ENCRYPTION_KEY.
    secretMinLength: 32,
    // PBKDF2 iterations for new accounts, and in prelogin for unknown emails.
    defaultKdfIterations: 600000,
    clientSecretLength: 30,
  },
  rateLimit: {
    // Failed logins before an account is locked, and for how long.
    loginMaxAttempts: 10,
    loginLockoutMinutes: 2,
  },
  cors: {
    preflightMaxAgeSeconds: 86400,
  },
  cache: {
    iconTtlSeconds: 604800,
  },
  performance: {
    // IDs per statement when moving ciphers in bulk.
    bulkMoveChunkSize: 200,
  },
  request: {
    // Body limit of the JSON routes; file uploads check their own.
    maxBodyBytes: 25 * 1024 * 1024,
  },
  compatibility: {
    // The version /config and /api/version report. Vaultwarden 1.37.0
    // reports 2026.6.0 for the response contract of Bitwarden 2026.7 clients.
    bitwardenServerVersion: '2026.6.0',
    // Official 2026.4 clients need this to receive and use cipher.key;
    // without it, items encrypted with their own key cannot be read.
    cipherKeyEncryptionFeatureEnabled: true,
  },
} as const;

export function getRefreshTokenSlidingTtlMs(clientType?: string | null): number {
  const normalized = String(clientType || '').trim().toLowerCase();
  if (normalized === 'web') return LIMITS.auth.refreshTokenWebSlidingTtlMs;
  if (normalized === 'mobile') return LIMITS.auth.refreshTokenMobileSlidingTtlMs;
  return LIMITS.auth.refreshTokenDefaultSlidingTtlMs;
}
