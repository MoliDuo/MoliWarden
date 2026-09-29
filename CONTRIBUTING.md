# Contributing to MoliWarden

Thanks for taking the time to improve MoliWarden.

MoliWarden is a Bitwarden-compatible server for Vercel with a custom web vault,
PostgreSQL storage, attachment storage, imports/exports, and scheduled backups.
Small changes can affect official clients, backups, migrations, or locale files,
so please keep changes focused and check the related parts of the project.

## Before Opening an Issue

For bug reports, include enough detail for someone else to reproduce the problem:

- The client or browser you used.
- The page, API route, or action that failed.
- Screenshots, logs, or the exact error message.
- Whether the problem happened after sync, import, export, restore, upgrade, or
  a fresh deployment.

Please do not report MoliWarden-specific problems to the official Bitwarden
team. This project is independent from Bitwarden.

## Pull Request Guidelines

Keep pull requests small enough to review. A good PR should explain:

- What changed and why.
- What user-facing behavior changed.
- Which related areas were checked.
- Which commands were run before submitting.

Avoid mixing unrelated refactors with feature or bug-fix work. If a cleanup is
needed before the real fix, mention that clearly in the PR.

## Areas That Need Extra Care

Some parts of the codebase are deliberately connected. When changing one of
these areas, check the related files before calling the work complete.

### Database Changes

The schema is defined by the migrations in `src/platform/db/migrations/`, and
its TypeScript shape by `src/platform/db/schema.ts`; keep the two in step.

If you add or change a table, column, or index:

- Add a new migration file and register it in `src/platform/db/migrate.ts`.
  Never edit a migration that has shipped.
- Prefer additive changes; the server applies pending migrations on its first
  request, while the previous deployment may still be serving.
- Queries are typed by Kysely, so `npm run typecheck` catches most mismatches;
  `npm run test:e2e` runs every migration on an empty database.
- Decide whether the data belongs in instance backups.

### Backup And Restore

Backups are whitelist-based: `src/modules/backup/archive.ts` lists every record
kind and field an archive carries, independent of the table layout. Transient
rows (sessions, rate limits, leases, consumed tokens) are never exported.

When adding persistent data, check:

- `src/modules/backup/archive.ts`
- `src/modules/backup/repo.ts`
- `webapp/src/lib/api/backup.ts`

### Secrets And Provider Settings

Provider credentials must not be stored or exported as plain JSON. Follow the
sealed settings in `src/modules/backup/settings-crypto.ts`, or document a
replacement design before changing it.

### Bitwarden Client Compatibility

Official Bitwarden clients may send or expect fields that are not used directly
by the web vault. Cipher and sync changes should preserve unknown client fields
unless they are known-invalid or server-owned.

Check these files when changing vault item shape or sync behavior:

- `src/modules/ciphers/model.ts`
- `src/modules/ciphers/responses.ts`
- `src/modules/sync/service.ts`

### Domain Rules

`users.custom_domains` holds the user's own equivalent-domain groups and
`users.excluded_global_domains` the global groups they turned off; the active
groups are derived from both when the rules are read.

### Accounts And Passwords

`users.master_password_hash` is for server-side login verification. It is not the
vault decryption key. Password changes, key material, `securityStamp`, and
refresh-token revocation must stay aligned.

Password hints are reminders, not recovery secrets. They must never contain the
master password, recovery codes, API keys, or anything that directly unlocks the
vault.

### i18n

Locale files are complete standalone bundles. When adding or changing user-facing
text, keep every locale in sync and run the validation script.

For new locales, update:

- `webapp/src/lib/i18n.ts`
- `webapp/src/lib/i18n/locales/*`
- `scripts/i18n-utils.cjs`

## Recommended Checks

For most backend or shared changes:

```sh
npx tsc -p tsconfig.json --noEmit
npm run build
```

For webapp text or locale changes:

```sh
npm run i18n:validate
npx tsc -p webapp/tsconfig.json --noEmit
npm run build
```

For documentation-only changes:

```sh
git diff --check
```
