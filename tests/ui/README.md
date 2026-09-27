# Web vault browser smoke suite

`tests/ui/smoke.mjs` drives the bundled web vault in Chromium through every
major page and flow and fails on:

- any failed step (a button, dialog or value that does not appear),
- uncaught page errors and `console.error` output,
- error toasts shown by the vault,
- any HTTP response >= 500 from the server or the S3 bucket, and any 4xx that
  the step does not explicitly expect,
- visible horizontal overflow on the phone-sized (375px) pass,
- raw i18n keys (`txt_...`, `nav_...`) on the main pages in Chinese.

It resets the `public` schema of its own database, creates its S3 bucket,
starts `scripts/dev-server.ts` against the built `dist/`, and registers every
account it uses (the first one becomes the instance admin; the second signs up
through an invite link minted on the admin page).

## Running

Start Postgres and S3 (`npm run test:services`, or any equivalent), then:

```sh
npm run test:ui                      # build + run inside the Playwright Docker image
SKIP_BUILD=1 npm run test:ui         # reuse the existing dist/
UI_ONLY=sends,tools npm run test:ui  # only some sections ("auth" always runs)
```

`scripts/test-ui.sh` installs `playwright-core` into `tests/ui/node_modules`
on first use (it is not a dependency of the server) and runs the suite in
`mcr.microsoft.com/playwright:v1.63.0-noble`, so the host needs no browser or
system libraries. Screenshots of failing steps and the server log are written
to `tests/ui/.artifacts/`.

Without Docker (e.g. on a CI runner), install a matching Chromium once and run
it directly:

```sh
npm install --prefix tests/ui --no-package-lock
tests/ui/node_modules/.bin/playwright-core install --with-deps chromium   # same as `npx playwright@1.63.0 install --with-deps chromium`
UI_NO_DOCKER=1 npm run test:ui
```

## Environment

| Variable | Default |
| --- | --- |
| `UI_DATABASE_URL` | `postgres://mw:mw@localhost:55432/mw_ui` (created if missing, schema dropped on every run) |
| `UI_S3_ENDPOINT` / `UI_S3_BUCKET` | `http://localhost:58333` / `mw-ui` |
| `UI_S3_ACCESS_KEY_ID` / `UI_S3_SECRET_ACCESS_KEY` | `mwaccess` / `mwsecret123` |
| `UI_PORT` | `8797` |
| `UI_ONLY` | comma-separated section names |
| `UI_STEP_TIMEOUT` | `15000` ms per action |
| `UI_ARTIFACTS` | `tests/ui/.artifacts` |

Nothing external is contacted: the breach check, backup destinations and
passkeys are opened but not exercised.
