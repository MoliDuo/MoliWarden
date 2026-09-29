import { attachDatabasePool } from '@vercel/functions';
import type pg from 'pg';
import { createPushService, type PushService } from '../modules/push/service';
import { createBlobStore, type BlobStore } from '../platform/blob';
import { createDb, createPool, type Db } from '../platform/db';
import { createRateLimiter, type RateLimiter } from '../platform/rate-limit';
import { createTokenService, type TokenService } from '../platform/tokens';
import type { Config } from './config';

// Everything a request handler may use, created once per process.
export interface Deps {
  config: Config;
  pool: pg.Pool;
  db: Db;
  tokens: TokenService;
  limiter: RateLimiter;
  push: PushService;
  blobs: BlobStore;
}

export function createDeps(config: Config): { deps: Deps; dispose(): Promise<void> } {
  const pool = createPool({ connectionString: config.databaseUrl, max: config.databasePoolMax });
  try {
    // Lets Vercel Fluid compute close idle connections before suspending.
    attachDatabasePool(pool);
  } catch {
    // Not on Vercel.
  }
  const db = createDb(pool);
  const push = createPushService(db, { disabled: config.pushRelayDisabled, installationDomain: config.webauthn.rpId });
  const deps: Deps = {
    config,
    pool,
    db,
    tokens: createTokenService(config.jwtSecret),
    limiter: createRateLimiter(db),
    push,
    blobs: createBlobStore(config.s3),
  };
  return { deps, dispose: () => pool.end() };
}
