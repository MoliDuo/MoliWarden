import { attachDatabasePool } from '@vercel/functions';
import type { Env } from '../types';
import { BackupTransferRunner } from '../durable/backup-transfer-runner';
import { createInProcessNamespace } from './in-process-object';
import { createPgPool, PgD1Database } from './pg-d1';

// Builds the runtime Env from process.env once per function instance.

let cachedEnv: Env | null = null;

function readDatabaseUrl(): string {
  const url =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.NEON_DATABASE_URL ||
    '';
  if (!url) {
    throw new Error('DATABASE_URL is not configured');
  }
  return url;
}

export function getEnv(): Env {
  if (cachedEnv) return cachedEnv;

  const pool = createPgPool({
    connectionString: readDatabaseUrl(),
    max: Number(process.env.DATABASE_POOL_MAX || 5) || 5,
  });
  try {
    // Lets Vercel Fluid compute close idle connections before suspending.
    attachDatabasePool(pool);
  } catch {
    // Not on Vercel.
  }

  const env: Env = {
    DB: new PgD1Database(pool),
    BACKUP_TRANSFER_RUNNER: createInProcessNamespace(
      () => env,
      (state, currentEnv) => new BackupTransferRunner(state, currentEnv)
    ),
    JWT_SECRET: process.env.JWT_SECRET || '',
    S3_ENDPOINT: process.env.S3_ENDPOINT,
    S3_BUCKET: process.env.S3_BUCKET,
    S3_ACCESS_KEY_ID: process.env.S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY: process.env.S3_SECRET_ACCESS_KEY,
    S3_REGION: process.env.S3_REGION,
    S3_FORCE_PATH_STYLE: process.env.S3_FORCE_PATH_STYLE,
    MAX_UPLOAD_BYTES: process.env.MAX_UPLOAD_BYTES,
    HIDE_WEB_VAULT: process.env.HIDE_WEB_VAULT,
    CRON_SECRET: process.env.CRON_SECRET,
    WEBAUTHN_RP_ID: process.env.WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME: process.env.WEBAUTHN_RP_NAME,
    WEBAUTHN_ALLOWED_ORIGINS: process.env.WEBAUTHN_ALLOWED_ORIGINS,
    YUBICO_VALIDATION_URLS: process.env.YUBICO_VALIDATION_URLS,
    globalSettings__yubico__validationUrls: process.env.globalSettings__yubico__validationUrls,
  };
  cachedEnv = env;
  return env;
}
