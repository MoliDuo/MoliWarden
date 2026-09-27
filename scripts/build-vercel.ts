// Produces a Vercel Build Output API v3 bundle in .vercel/output:
//   static/                 web vault (vite build of webapp/)
//   functions/index.func/   the whole API bundled into one Node function
//   config.json             routing (API paths -> function, SPA fallback) + cron
//
// Run with: npm run build:vercel
import { build } from 'esbuild';
import { execSync } from 'node:child_process';
import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { BACKEND_EXACT_PATHS, BACKEND_PATH_PREFIXES } from '../src/web-vault-visibility';

const root = process.cwd();
const out = join(root, '.vercel', 'output');
const funcDir = join(out, 'functions', 'index.func');
const hideWebVault = String(process.env.HIDE_WEB_VAULT || '').trim() === '1';
// Hobby plans only allow daily cron jobs; override for Pro (e.g. "*/15 * * * *").
const cronSchedule = String(process.env.MOLIWARDEN_CRON_SCHEDULE || '').trim() || '17 3 * * *';

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function main(): Promise<void> {
  await rm(out, { recursive: true, force: true });
  await mkdir(funcDir, { recursive: true });

  if (!hideWebVault) {
    execSync('npx vite build --config webapp/vite.config.ts', { stdio: 'inherit' });
    await cp(join(root, 'dist'), join(out, 'static'), { recursive: true });
  } else {
    await mkdir(join(out, 'static'), { recursive: true });
  }

  await build({
    entryPoints: [join(root, 'vercel', 'function-entry.ts')],
    outfile: join(funcDir, 'index.mjs'),
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    sourcemap: 'linked',
    minify: false,
    external: ['pg-native'],
    // Some bundled CommonJS dependencies (pg) call require() at runtime.
    banner: {
      js: "import { createRequire as __nwCreateRequire } from 'node:module'; const require = __nwCreateRequire(import.meta.url);",
    },
    logLevel: 'info',
  });

  await writeFile(
    join(funcDir, '.vc-config.json'),
    JSON.stringify(
      {
        runtime: 'nodejs22.x',
        handler: 'index.mjs',
        launcherType: 'Nodejs',
        shouldAddHelpers: false,
        supportsResponseStreaming: true,
        maxDuration: Number(process.env.MOLIWARDEN_MAX_DURATION || 60) || 60,
      },
      null,
      2
    )
  );

  const prefixPattern = BACKEND_PATH_PREFIXES.map((prefix) => escapeRegex(prefix.slice(1))).join('|');
  const exactPattern = Array.from(BACKEND_EXACT_PATHS).map(escapeRegex).join('|');
  const backendSrc = `^(/(?:${prefixPattern})(?:/.*)?|${exactPattern})/?$`;

  const config = {
    version: 3,
    routes: [
      {
        src: '^/(.*)$',
        headers: { 'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet' },
        continue: true,
      },
      { src: backendSrc, dest: '/index?__nwpath=$1' },
      { handle: 'filesystem' },
      ...(hideWebVault
        ? [{ src: '^/(.*)$', status: 404, dest: '/404' }]
        : [
            { src: '^/assets/(.*)$', status: 404 },
            { src: '^/(.*)$', dest: '/index.html' },
          ]),
    ],
    crons: [{ path: '/api/internal/cron', schedule: cronSchedule }],
  };
  await writeFile(join(out, 'config.json'), JSON.stringify(config, null, 2));
  console.log(`Vercel output written to ${out}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
