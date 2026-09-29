import { z } from 'zod';
import { LIMITS } from '../config/limits';

// The deployment's settings, read once from the environment variables (on
// Vercel: the project's Environment Variables). Nothing else in src/ reads
// process.env.
//
// Only a missing database is fatal. A missing or weak JWT_SECRET and missing
// S3 settings are reported by the features that need them, so a half-set-up
// deployment can still tell its operator what to fix.

export type Source = Record<string, string | undefined>;

export interface S3Config {
  endpoint?: string;
  bucket?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  region?: string;
  forcePathStyle?: string;
}

export type IconSource = 'favicon' | 'bitwarden' | 'off';

export interface Config {
  databaseUrl: string;
  databasePoolMax: number;
  jwtSecret: string;
  jwtSecretProblem: 'missing' | 'too_short' | null;
  s3: S3Config;
  // The largest attachment or Send file; Vercel Functions take bodies of up
  // to 4.5 MB.
  maxUploadBytes: number;
  showPasswordHint: boolean;
  iconSource: IconSource;
  // Mobile apps are woken up through Bitwarden's push relay unless this is set.
  pushRelayDisabled: boolean;
  cronSecret?: string;
  // Lets backup destinations point at private or loopback addresses. For
  // tests and self-hosted setups whose storage sits on the same network.
  backupAllowPrivateHosts: boolean;
  webauthn: { rpId?: string; rpName?: string; allowedOrigins?: string };
  yubicoValidationUrls?: string;
}

export class ConfigError extends Error {}

const text = z
  .string()
  .optional()
  .transform((value) => value?.trim() || undefined);
const flag = text.transform((value) => value === '1' || value === 'true');

const schema = z.object({
  DATABASE_URL: text,
  POSTGRES_URL: text,
  NEON_DATABASE_URL: text,
  DATABASE_POOL_MAX: text.transform((value) => (value === undefined ? 5 : Number(value))).pipe(z.number().int().positive()),
  JWT_SECRET: text,
  S3_ENDPOINT: text,
  S3_BUCKET: text,
  S3_ACCESS_KEY_ID: text,
  S3_SECRET_ACCESS_KEY: text,
  S3_REGION: text,
  S3_FORCE_PATH_STYLE: text,
  MAX_UPLOAD_BYTES: text.transform((value) => (value === undefined ? 4_400_000 : Number(value))).pipe(z.number().int().positive()),
  SHOW_PASSWORD_HINT: flag,
  ICON_SOURCE: z.enum(['favicon', 'bitwarden', 'off']).default('favicon'),
  PUSH_RELAY_DISABLED: flag,
  CRON_SECRET: text,
  BACKUP_ALLOW_PRIVATE_HOSTS: flag,
  WEBAUTHN_RP_ID: text,
  WEBAUTHN_RP_NAME: text,
  WEBAUTHN_ALLOWED_ORIGINS: text,
  YUBICO_VALIDATION_URLS: text,
  globalSettings__yubico__validationUrls: text,
});

export function readConfig(source: Source): Config {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new ConfigError(`${issue.path.join('.')} is invalid: ${issue.message}`);
  }
  const env = parsed.data;
  const databaseUrl = env.DATABASE_URL ?? env.POSTGRES_URL ?? env.NEON_DATABASE_URL;
  if (!databaseUrl) throw new ConfigError('DATABASE_URL is not configured');

  const jwtSecret = env.JWT_SECRET ?? '';
  return {
    databaseUrl,
    databasePoolMax: env.DATABASE_POOL_MAX,
    jwtSecret,
    jwtSecretProblem: !jwtSecret ? 'missing' : jwtSecret.length < LIMITS.auth.jwtSecretMinLength ? 'too_short' : null,
    s3: {
      endpoint: env.S3_ENDPOINT,
      bucket: env.S3_BUCKET,
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
      region: env.S3_REGION,
      forcePathStyle: env.S3_FORCE_PATH_STYLE,
    },
    maxUploadBytes: env.MAX_UPLOAD_BYTES,
    showPasswordHint: env.SHOW_PASSWORD_HINT,
    iconSource: env.ICON_SOURCE,
    pushRelayDisabled: env.PUSH_RELAY_DISABLED,
    cronSecret: env.CRON_SECRET,
    backupAllowPrivateHosts: env.BACKUP_ALLOW_PRIVATE_HOSTS,
    webauthn: { rpId: env.WEBAUTHN_RP_ID, rpName: env.WEBAUTHN_RP_NAME, allowedOrigins: env.WEBAUTHN_ALLOWED_ORIGINS },
    yubicoValidationUrls: env.YUBICO_VALIDATION_URLS ?? env.globalSettings__yubico__validationUrls,
  };
}
