#!/usr/bin/env node
// Keeps the web vault monochrome: colours are defined once, as tokens, and
// everything else refers to them.
//
// - Stylesheets may not contain colour literals (hex, rgb/hsl functions, or
//   named colours) outside tokens.css and card-brands.css (bank logos keep
//   their brand colours).
// - Neither stylesheets nor components may use Tailwind palette classes such as
//   `bg-white` or `text-slate-500`; the token aliases in tailwind.config.js
//   (`bg-panel`, `text-muted`, ...) are the only colour utilities.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const STYLES = join(ROOT, 'webapp/src/styles');
const SOURCES = join(ROOT, 'webapp/src');
const COLOR_SOURCES = new Set(['tokens.css', 'card-brands.css']);

const COLOR_LITERAL = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(|(?<![\w-])(?:white|black)(?![\w-])/gi;
const PALETTE = 'slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose';
const PALETTE_CLASS = new RegExp(
  `(?<![\\w-])(?:[a-z-]+:)*(?:bg|text|border|ring|fill|stroke|from|via|to|outline|divide|accent|caret|decoration|placeholder|shadow)-(?:(?:${PALETTE})-\\d{2,3}|white|black)\\b`,
  'g',
);

function walk(dir, ext) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return walk(path, ext);
    return path.endsWith(ext) ? [path] : [];
  });
}

function stripComments(css) {
  // Keep line numbers stable by replacing comment bodies with blank lines.
  return css.replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ' '));
}

const problems = [];
function report(file, source, index, match, kind) {
  const line = source.slice(0, index).split('\n').length;
  problems.push(`${relative(ROOT, file)}:${line}: ${kind} "${match}"`);
}

for (const file of walk(STYLES, '.css')) {
  const css = stripComments(readFileSync(file, 'utf8'));
  const name = file.slice(STYLES.length + 1);
  if (!COLOR_SOURCES.has(name)) {
    for (const m of css.matchAll(COLOR_LITERAL)) report(file, css, m.index, m[0], 'colour literal');
  }
  for (const m of css.matchAll(PALETTE_CLASS)) report(file, css, m.index, m[0], 'palette class');
}

for (const file of walk(SOURCES, '.tsx')) {
  const source = readFileSync(file, 'utf8');
  for (const m of source.matchAll(PALETTE_CLASS)) report(file, source, m.index, m[0], 'palette class');
}

if (problems.length) {
  console.error(`Found ${problems.length} colour(s) outside the design tokens:\n${problems.join('\n')}`);
  console.error('\nUse a token from webapp/src/styles/tokens.css instead.');
  process.exit(1);
}
console.log('CSS colours: all values come from design tokens.');
