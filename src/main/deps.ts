import { attachDatabasePool } from '@vercel/functions';
import type pg from 'pg';
import { createDb, type Db } from '../platform/db';
import { createLegacyEnv } from '../platform/env';
import { createPgPool } from '../platform/pg-d1';
import { createRateLimiter, type RateLimiter } from '../platform/rate-limit';
import { createTokenService, type TokenService } from '../platform/tokens';
import type { Env } from '../types';
import type { Config } from './config';

// Everything a request handler may use, created once per process.
export interface Deps {
  config: Config;
  pool: pg.Pool;
  db: Db;
  tokens: TokenService;
  limiter: RateLimiter;
  // For the handlers that have not been ported to src/modules yet.
  legacyEnv: Env;
}

export function createDeps(config: Config): { deps: Deps; dispose(): Promise<void> } {
  const pool = createPgPool({ connectionString: config.databaseUrl, max: config.databasePoolMax });
  try {
    // Lets Vercel Fluid compute close idle connections before suspending.
    attachDatabasePool(pool);
  } catch {
    // Not on Vercel.
  }
  const db = createDb(pool);
  const deps: Deps = {
    config,
    pool,
    db,
    tokens: createTokenService(config.jwtSecret),
    limiter: createRateLimiter(db),
    legacyEnv: createLegacyEnv(config, pool),
  };
  return { deps, dispose: () => pool.end() };
}
