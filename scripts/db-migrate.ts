// Brings the database schema up to date. The server does the same on its
// first request; this is for doing it ahead of a deployment.
//
//   DATABASE_URL=postgres://... npm run db:migrate
//
// DATABASE_URL_UNPOOLED, when set, is used instead: a direct connection
// suits schema changes better than a transaction pooler.
import { readConfig } from '../src/main/config';
import { createDb, createPool } from '../src/platform/db';
import { migrateToLatest, schemaState } from '../src/platform/db/migrate';

const config = readConfig(process.env);
const pool = createPool({ connectionString: process.env.DATABASE_URL_UNPOOLED?.trim() || config.databaseUrl, max: 1 });
const db = createDb(pool);
try {
  if ((await schemaState(db)) === 'legacy') {
    console.error('This database holds the tables of an earlier MoliWarden version. Run `npm run db:migrate-legacy` instead.');
    process.exitCode = 1;
  } else {
    const applied = await migrateToLatest(pool);
    console.log(applied.length ? `Applied ${applied.join(', ')}.` : 'The schema is up to date.');
  }
} finally {
  await db.destroy();
}
