#!/usr/bin/env bash
# Browser smoke suite for the web vault (tests/ui/smoke.mjs).
#
# Builds dist/, installs playwright-core into tests/ui/node_modules on first use,
# then runs the suite inside the official Playwright image so no browser or
# system libraries are needed on the host. The suite resets its own database
# schema (UI_DATABASE_URL, default postgres://mw:mw@localhost:55432/mw_ui) and
# starts its own server on UI_PORT (default 8797).
#
#   npm run test:ui                     # build + run in Docker
#   SKIP_BUILD=1 npm run test:ui        # reuse the existing dist/
#   UI_ONLY=vault,sends npm run test:ui # run selected sections (auth always runs)
#   UI_NO_DOCKER=1 npm run test:ui      # use a locally installed Chromium, see tests/ui/README.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLAYWRIGHT_VERSION="1.63.0"
IMAGE="${UI_PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble}"
cd "$ROOT"

if [ "${SKIP_BUILD:-}" != "1" ]; then
  npm run build
fi

if [ ! -f tests/ui/node_modules/playwright-core/package.json ]; then
  npm install --prefix tests/ui --no-audit --no-fund --no-package-lock
fi

if [ "${UI_NO_DOCKER:-}" = "1" ]; then
  exec node tests/ui/smoke.mjs
fi

mounts=(-v "$ROOT:$ROOT")
# node_modules may be a symlink into another checkout (git worktrees); mount its target too.
if [ -L node_modules ]; then
  target="$(readlink -f node_modules)"
  mounts+=(-v "$target:$target:ro")
fi

env_args=()
while IFS='=' read -r name _; do
  env_args+=(-e "$name")
done < <(env | grep -E '^UI_' || true)

exec docker run --rm --init --network host --ipc host \
  --user "$(id -u):$(id -g)" -e HOME=/tmp \
  "${mounts[@]}" "${env_args[@]}" -w "$ROOT" \
  "$IMAGE" node tests/ui/smoke.mjs
