// The layering of src/, checked on the imports and a few constructs of every
// file. See CONTRIBUTING.md ("Backend layout").
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SRC = join(ROOT, 'src');

interface SourceFile {
  path: string; // relative to the repository, with forward slashes
  text: string;
  imports: string[]; // resolved, relative to the repository; packages as they are
}

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return walk(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts') ? [path] : [];
  });
}

const files: SourceFile[] = walk(SRC).map((path) => {
  const text = readFileSync(path, 'utf8');
  const imports = [...text.matchAll(/^(?:import|export)\s[^;]*?from\s+'([^']+)'/gms)].map(([, spec]) =>
    spec.startsWith('.') ? relative(ROOT, resolve(dirname(path), spec)).replaceAll('\\', '/') : spec,
  );
  return { path: relative(ROOT, path).replaceAll('\\', '/'), text, imports };
});

const layer = (path: string) => path.split('/')[1];
const isRoutes = (path: string) => /^src\/modules\/[^/]+\/routes$/.test(path.replace(/\.ts$/, ''));
const isRepo = (path: string) => /\/repo(\.ts)?$/.test(path);

function violations(check: (file: SourceFile) => string[]): string[] {
  return files.flatMap((file) => check(file).map((problem) => `${file.path}: ${problem}`));
}

test('the platform layer knows nothing of the layers above it', () => {
  assert.deepEqual(
    violations((file) =>
      layer(file.path) === 'platform' ? file.imports.filter((spec) => /^src\/(main|http|modules)\//.test(spec)) : [],
    ),
    [],
  );
});

test('HTTP code stays in routes, middleware and the app', () => {
  // A service takes (deps, caller, input) and never sees a request context.
  assert.deepEqual(
    violations((file) =>
      ['http', 'main'].includes(layer(file.path)) || isRoutes(file.path) ? [] : file.imports.filter((spec) => spec === 'hono' || spec.startsWith('hono/')),
    ),
    [],
  );
});

test('routes and middleware call services, not repositories', () => {
  assert.deepEqual(
    violations((file) => (isRoutes(file.path) || layer(file.path) === 'http' ? file.imports.filter(isRepo) : [])),
    [],
  );
});

test('SQL is written in repositories and the database platform only', () => {
  const allowed = (path: string) => isRepo(path) || path.startsWith('src/platform/db/') || path === 'src/platform/rate-limit.ts';
  assert.deepEqual(
    violations((file) =>
      allowed(file.path) ? [] : /\b(selectFrom|insertInto|updateTable|deleteFrom)\(|\bsql`/.test(file.text) ? ['builds a query'] : [],
    ),
    [],
  );
});

test('the environment is read in one place', () => {
  const readers = files.filter((file) => /\bprocess\.env\b/.test(file.text)).map((file) => file.path);
  // node.ts only hands process.env to config.ts as the default source.
  assert.deepEqual(readers.sort(), ['src/main/config.ts', 'src/main/node.ts']);
});

test('no mutable state at module level', () => {
  // One process serves many requests (and, in tests, many apps): state lives
  // in Deps, created per app, or in the database. Constant lookup Sets are fine.
  assert.deepEqual(
    violations((file) =>
      [...file.text.matchAll(/^(?:export\s+)?(?:let\s+\w+|(?:const|var)\s+\w+(?::[^=]+)?\s*=\s*new\s+(?:Map|WeakMap)\b)/gm)].map(([line]) => line),
    ),
    [],
  );
});
