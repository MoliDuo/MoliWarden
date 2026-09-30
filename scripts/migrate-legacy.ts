// Moves a database of the earlier version onto today's schema. See the
// README ("Upgrading from an earlier version") for the whole procedure.
//
//   npm run db:migrate-legacy -- --dry-run    convert and check, then undo
//   npm run db:migrate-legacy                 migrate
//   npm run db:migrate-legacy -- --rollback   put the old tables back
//   npm run db:migrate-legacy -- --migrate-remote-index
//                                             after migrating: copy the attachment
//                                             index of each backup destination
//
// Reads DATABASE_URL (DATABASE_URL_UNPOOLED when set), ENCRYPTION_KEY, and
// JWT_SECRET: the one the earlier version ran with, which opens its backup
// settings.
import { readConfig } from '../src/main/config';
import { createSecretBox } from '../src/platform/crypto';
import { createDb, createPool } from '../src/platform/db';
import { MigrationError, migrateLegacy, migrateRemoteIndexes, rollbackLegacy } from './legacy/migrate';
import { printReport } from './legacy/report';

const flags = new Set(process.argv.slice(2));
const known = ['--dry-run', '--rollback', '--migrate-remote-index'];
const unknown = [...flags].filter((flag) => !known.includes(flag));
if (unknown.length) {
  console.error(`Unknown option ${unknown[0]}. Options: ${known.join(', ')}`);
  process.exit(2);
}

const config = readConfig(process.env);
if (config.encryptionKeyProblem) {
  console.error('ENCRYPTION_KEY is not set or too weak: set the one the new version will run with.');
  process.exit(2);
}
const secrets = createSecretBox(config.encryptionKey);
const pool = createPool({ connectionString: process.env.DATABASE_URL_UNPOOLED?.trim() || config.databaseUrl, max: 1 });

try {
  if (flags.has('--rollback')) {
    await rollbackLegacy(pool);
    console.log('The tables of the earlier version are back in place. Deploy the earlier version again.');
  } else if (flags.has('--migrate-remote-index')) {
    const db = createDb(pool);
    const results = await migrateRemoteIndexes(db, secrets, config.backupAllowPrivateHosts);
    if (!results.length) console.log('No backup destinations, or their settings still need repairing in the web vault.');
    for (const result of results) console.log(`${result.destination}: ${result.outcome}`);
  } else {
    if (config.jwtSecretProblem) console.warn('JWT_SECRET is not set: the backup settings cannot be carried over and will need repairing.');
    const result = await migrateLegacy(pool, { secrets, jwtSecret: config.jwtSecret, dryRun: flags.has('--dry-run') });
    console.log(result.status === 'dry-run' ? 'Dry run: nothing was changed.\n' : 'Migrated.\n');
    console.log('Rows read from the earlier tables:');
    for (const [table, count] of Object.entries(result.read)) console.log(`  ${table}: ${count}`);
    console.log('\nRows written:');
    for (const [table, count] of Object.entries(result.written)) console.log(`  ${table}: ${count}`);
    printReport(result.report);
    if (result.status === 'migrated') console.log('\nThe earlier tables are kept in the schema "legacy" for --rollback.');
  }
} catch (error) {
  if (!(error instanceof MigrationError)) throw error;
  console.error(error.message);
  process.exitCode = 1;
} finally {
  await pool.end();
}
