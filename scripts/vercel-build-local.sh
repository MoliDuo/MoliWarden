#!/usr/bin/env bash
# Runs the official `vercel build` without a Vercel account, producing the
# .vercel/output exactly as a deployment would (Vercel post-processes our
# config.json). Used by CI before the smoke test:
#   scripts/vercel-build-local.sh && npx tsx --test tests/vercel-output.smoke.test.ts
# Note: `vercel build` runs vercel.json's installCommand (npm ci).
set -euo pipefail
cd "$(dirname "$0")/.."
VERCEL_CLI_VERSION="${VERCEL_CLI_VERSION:-60.1.3}"
mkdir -p .vercel
if [ ! -f .vercel/project.json ]; then
  cat > .vercel/project.json <<'JSON'
{"projectId":"prj_local_build","orgId":"team_local_build","settings":{"framework":null,"nodeVersion":"22.x"}}
JSON
  trap 'rm -f .vercel/project.json' EXIT
fi
npx -y "vercel@${VERCEL_CLI_VERSION}" build --yes
