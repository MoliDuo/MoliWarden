import { attachDatabasePool } from '@vercel/functions';
import type { Env } from '../types';
import { BackupTransferRunner } from '../durable/backup-transfer-runner';
import { createInProcessNamespace } from './in-process-object';
import { createPgPool, PgD1Database } from './pg-d1';

// Builds the runtime Env from a set of environment variables.

type Source = Record<string, string | undefined>;

function readDatabaseUrl(source: Source): string {
  const url = source.DATABASE_URL || source.POSTGRES_URL || source.NEON_DATABASE_URL || '';
  if (!url) {
    throw new Error('DATABASE_URL is not configured');
  }
  return url;
}

export function createEnv(source: Source): { env: Env; dispose(): Promise<void> } {
  const pool = createPgPool({
    connectionString: readDatabaseUrl(source),
    max: Number(source.DATABASE_POOL_MAX || 5) || 5,
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
    JWT_SECRET: source.JWT_SECRET || '',
    S3_ENDPOINT: source.S3_ENDPOINT,
    S3_BUCKET: source.S3_BUCKET,
    S3_ACCESS_KEY_ID: source.S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY: source.S3_SECRET_ACCESS_KEY,
    S3_REGION: source.S3_REGION,
    S3_FORCE_PATH_STYLE: source.S3_FORCE_PATH_STYLE,
    MAX_UPLOAD_BYTES: source.MAX_UPLOAD_BYTES,
    HIDE_WEB_VAULT: source.HIDE_WEB_VAULT,
    SHOW_PASSWORD_HINT: source.SHOW_PASSWORD_HINT,
    CRON_SECRET: source.CRON_SECRET,
    WEBAUTHN_RP_ID: source.WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME: source.WEBAUTHN_RP_NAME,
    WEBAUTHN_ALLOWED_ORIGINS: source.WEBAUTHN_ALLOWED_ORIGINS,
    YUBICO_VALIDATION_URLS: source.YUBICO_VALIDATION_URLS,
    globalSettings__yubico__validationUrls: source.globalSettings__yubico__validationUrls,
  };
  return { env, dispose: () => pool.end() };
}
