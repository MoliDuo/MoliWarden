import type pg from 'pg';
import type { Config } from '../main/config';
import type { PushService } from '../modules/push/service';
import type { Env } from '../types';
import { BackupTransferRunner } from '../durable/backup-transfer-runner';
import { createInProcessNamespace } from './in-process-object';
import { PgD1Database } from './pg-d1';

// The Env object the handlers that have not been ported yet expect, built
// from the parsed configuration.
export function createLegacyEnv(config: Config, pool: pg.Pool, push: PushService): Env {
  const flag = (value: boolean) => (value ? '1' : undefined);
  const env: Env = {
    DB: new PgD1Database(pool),
    PUSH: push,
    BACKUP_TRANSFER_RUNNER: createInProcessNamespace(
      () => env,
      (state, currentEnv) => new BackupTransferRunner(state, currentEnv)
    ),
    JWT_SECRET: config.jwtSecret,
    S3_ENDPOINT: config.s3.endpoint,
    S3_BUCKET: config.s3.bucket,
    S3_ACCESS_KEY_ID: config.s3.accessKeyId,
    S3_SECRET_ACCESS_KEY: config.s3.secretAccessKey,
    S3_REGION: config.s3.region,
    S3_FORCE_PATH_STYLE: config.s3.forcePathStyle,
    MAX_UPLOAD_BYTES: String(config.maxUploadBytes),
    SHOW_PASSWORD_HINT: flag(config.showPasswordHint),
    CRON_SECRET: config.cronSecret,
    WEBAUTHN_RP_ID: config.webauthn.rpId,
    WEBAUTHN_RP_NAME: config.webauthn.rpName,
    WEBAUTHN_ALLOWED_ORIGINS: config.webauthn.allowedOrigins,
    YUBICO_VALIDATION_URLS: config.yubicoValidationUrls,
  };
  return env;
}
