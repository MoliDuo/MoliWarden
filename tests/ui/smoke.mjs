// Browser smoke suite for the bundled web vault.
//
// Resets its own PostgreSQL schema, starts `scripts/dev-server.ts` against the
// built dist/, then drives Chromium through every major page and flow. Any
// uncaught page error, console error, error toast, backend 5xx or unexpected
// backend 4xx fails the run, as does any failed step.
//
// Usually run through `npm run test:ui` (scripts/test-ui.sh), which builds the
// web vault and runs this file inside the Playwright Docker image. See
// tests/ui/README.md for the environment variables and the non-Docker path.
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, createWriteStream, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { AwsClient } from 'aws4fetch';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const env = process.env;
const DATABASE_URL = env.UI_DATABASE_URL || 'postgres://mw:mw@localhost:55432/mw_ui';
const S3_ENDPOINT = env.UI_S3_ENDPOINT || 'http://localhost:58333';
const S3_BUCKET = env.UI_S3_BUCKET || 'mw-ui';
const S3_ACCESS_KEY_ID = env.UI_S3_ACCESS_KEY_ID || 'mwaccess';
const S3_SECRET_ACCESS_KEY = env.UI_S3_SECRET_ACCESS_KEY || 'mwsecret123';
const PORT = Number(env.UI_PORT || 8797);
const BASE = `http://localhost:${PORT}`;
const ARTIFACTS = env.UI_ARTIFACTS || join(ROOT, 'tests', 'ui', '.artifacts');
const ONLY = (env.UI_ONLY || '').split(',').map((s) => s.trim()).filter(Boolean);
const PASSWORD = 'Correct-Horse-Battery-9';
const STEP_TIMEOUT = Number(env.UI_STEP_TIMEOUT || 15000);

rmSync(ARTIFACTS, { recursive: true, force: true });
mkdirSync(ARTIFACTS, { recursive: true });

// ---------------------------------------------------------------------------
// Environment: fresh schema, bucket, server
// ---------------------------------------------------------------------------

async function resetDatabase() {
  let client = new pg.Client({ connectionString: DATABASE_URL });
  try {
    await client.connect();
  } catch (error) {
    if (error?.code !== '3D000') throw error;
    // Database does not exist yet (e.g. a fresh tests/services Postgres): create it.
    const url = new URL(DATABASE_URL);
    const name = decodeURIComponent(url.pathname.slice(1));
    url.pathname = '/postgres';
    const admin = new pg.Client({ connectionString: url.toString() });
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE "${name.replace(/"/g, '""')}"`);
    } finally {
      await admin.end();
    }
    client = new pg.Client({ connectionString: DATABASE_URL });
    await client.connect();
  }
  try {
    await client.query('DROP SCHEMA IF EXISTS public CASCADE');
    await client.query('CREATE SCHEMA public');
  } finally {
    await client.end();
  }
}

async function ensureBucket() {
  const aws = new AwsClient({ accessKeyId: S3_ACCESS_KEY_ID, secretAccessKey: S3_SECRET_ACCESS_KEY, region: 'us-east-1', service: 's3' });
  const response = await aws.fetch(`${S3_ENDPOINT}/${S3_BUCKET}`, { method: 'PUT' });
  if (!response.ok && response.status !== 409) {
    throw new Error(`Could not create bucket ${S3_BUCKET}: ${response.status} ${await response.text()}`);
  }
}

let serverProcess = null;
const serverLogPath = join(ARTIFACTS, 'server.log');

async function startServer() {
  const log = createWriteStream(serverLogPath);
  serverProcess = spawn(join(ROOT, 'node_modules', '.bin', 'tsx'), ['scripts/dev-server.ts'], {
    cwd: ROOT,
    env: {
      ...env,
      DATABASE_URL,
      JWT_SECRET: 'ui-smoke-secret-ui-smoke-secret-0123456789',
      S3_ENDPOINT,
      S3_BUCKET,
      S3_ACCESS_KEY_ID,
      S3_SECRET_ACCESS_KEY,
      S3_REGION: 'us-east-1',
      PUSH_RELAY_DISABLED: '1',
      PORT: String(PORT),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  serverProcess.stdout.pipe(log);
  serverProcess.stderr.pipe(log);
  serverProcess.on('exit', (code) => {
    if (code !== null && code !== 0 && !shuttingDown) console.error(`server exited with ${code}; see ${serverLogPath}`);
  });
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${BASE}/api/config`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`server did not come up on ${BASE}; see ${serverLogPath}`);
}

let shuttingDown = false;
function stopServer() {
  shuttingDown = true;
  serverProcess?.kill('SIGTERM');
}

// ---------------------------------------------------------------------------
// Problem collection
// ---------------------------------------------------------------------------

const problems = [];
const failures = [];
let currentStep = '(setup)';
// Backend 4xx responses that a step expects: [{ method, path: RegExp, status }]
let expected4xx = [
  // The realtime hub is not available on serverless deployments; the vault probes once and falls back to sync.
  { method: 'POST', path: /^\/notifications\/hub\/negotiate$/, status: 404 },
  // Website icons: the proxy answers 404 when a site has no icon; the vault falls back to a generic glyph.
  { method: 'GET', path: /^\/icons\//, status: 404 },
];

function problem(who, text) {
  const entry = `[${currentStep}] ${who}: ${text}`;
  problems.push(entry);
  console.log(`  !! ${who}: ${text}`);
}

// Everything served by our server or the S3 bucket is judged; third-party hosts are not.
function isBackendUrl(url) {
  try {
    const origin = new URL(url).origin;
    return origin === BASE || origin === new URL(S3_ENDPOINT).origin;
  } catch {
    return false;
  }
}

function watch(page, who) {
  page.on('pageerror', (error) => problem(who, `pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    const text = message.text();
    // The browser logs every non-2xx fetch as a console error; those are judged by the response hook.
    if (/^Failed to load resource: the server responded with a status of 4\d\d/.test(text)) return;
    problem(who, `console.error: ${text}`);
  });
  page.on('response', (response) => {
    const url = response.url();
    if (!isBackendUrl(url)) return;
    const status = response.status();
    const method = response.request().method();
    const path = new URL(url).pathname;
    if (status >= 500) {
      problem(who, `HTTP ${status} ${method} ${path}`);
    } else if (status >= 400) {
      const ok = expected4xx.some((rule) => rule.status === status && (!rule.method || rule.method === method) && rule.path.test(path));
      if (!ok) problem(who, `unexpected HTTP ${status} ${method} ${path}`);
    }
  });
}

async function expecting4xx(rules, fn) {
  const saved = expected4xx;
  expected4xx = [...expected4xx, ...rules];
  try {
    return await fn();
  } finally {
    expected4xx = saved;
  }
}

// ---------------------------------------------------------------------------
// Browser helpers
// ---------------------------------------------------------------------------

const browser = await chromium.launch({ args: ['--disable-dev-shm-usage'] });
const pages = [];

async function newPage(who, options = {}) {
  const context = await browser.newContext({
    locale: 'en-US',
    viewport: { width: 1400, height: 900 },
    acceptDownloads: true,
    ...options,
  });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });
  // Surface error toasts as problems: the vault reports most failed actions only through them.
  await context.exposeBinding('__uiSmokeToast', (_source, type, text) => {
    if (type === 'error' && !allowErrorToast) problem(who, `error toast: ${text}`);
    else console.log(`  .. ${who} toast(${type}): ${text}`);
  });
  await context.addInitScript(() => {
    const seen = new WeakSet();
    new MutationObserver(() => {
      for (const node of document.querySelectorAll('.toast-item')) {
        if (seen.has(node)) continue;
        seen.add(node);
        const type = ['error', 'success', 'warning', 'info'].find((c) => node.classList.contains(c)) || 'info';
        window.__uiSmokeToast(type, node.querySelector('.toast-text')?.textContent || '');
      }
    }).observe(document, { childList: true, subtree: true });
  });
  const page = await context.newPage();
  page.setDefaultTimeout(STEP_TIMEOUT);
  watch(page, who);
  page.who = who;
  pages.push(page);
  return page;
}

let allowErrorToast = false;
async function allowingErrorToast(fn) {
  allowErrorToast = true;
  try {
    return await fn();
  } finally {
    allowErrorToast = false;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(`assertion failed: ${message}`);
}

async function shot(page, name) {
  await page.screenshot({ path: join(ARTIFACTS, `${name}.png`), fullPage: false }).catch(() => {});
}

// In-app navigation. A full page load locks the vault (keys live in memory), so
// prefer the sidebar link and fall back to a history push that wouter picks up.
async function go(page, path) {
  const link = page.locator(`.app-side a[href="${path}"]`).first();
  if (await link.isVisible().catch(() => false)) {
    await link.click();
  } else {
    await page.evaluate((target) => {
      window.history.pushState(null, '', target);
      window.dispatchEvent(new PopStateEvent('popstate'));
    }, path);
  }
  await page.waitForURL((url) => url.pathname === path);
  await settle(page);
}

// Wait for lazy route chunks and loading skeletons to go away.
async function settle(page) {
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.locator('.loading-state, .skeleton').first().waitFor({ state: 'detached', timeout: STEP_TIMEOUT }).catch(() => {});
}

function dialog(page) {
  return page.locator('.dialog-card.open').last();
}

async function confirmDialog(page, buttonText) {
  const card = dialog(page);
  await card.waitFor();
  if (buttonText) await card.getByRole('button', { name: buttonText, exact: true }).click();
  else await card.locator('[data-dialog-confirm="true"]').click();
  await card.waitFor({ state: 'detached' }).catch(() => {});
}

async function waitToast(page, pattern) {
  await page.locator('.toast-item', { hasText: pattern }).first().waitFor();
}

function field(scope, label) {
  return scope.locator('label.field', { has: scope.page().locator(`xpath=./span[normalize-space(.)=${JSON.stringify(label)}]`) }).locator('input, textarea, select').first();
}

// Elements under `selector` whose content visibly spills past their own box
// (overflow-x: visible), plus page-level horizontal scrolling.
async function findOverflow(page, selector) {
  return page.evaluate((sel) => {
    const found = [];
    const describe = (el) => {
      const cls = typeof el.className === 'string' && el.className.trim() ? `.${el.className.trim().split(/\s+/).join('.')}` : '';
      return `${el.tagName.toLowerCase()}${cls} "${(el.textContent || '').trim().slice(0, 40)}"`;
    };
    if (document.documentElement.scrollWidth > window.innerWidth + 1) {
      found.push(`page scrolls horizontally (${document.documentElement.scrollWidth}px > ${window.innerWidth}px)`);
    }
    for (const root of document.querySelectorAll(sel)) {
      for (const el of [root, ...root.querySelectorAll('*')]) {
        if (el.closest('svg') || !el.clientWidth) continue;
        const style = getComputedStyle(el);
        if (style.overflowX !== 'visible' || style.visibility === 'hidden') continue;
        if (el.scrollWidth > el.clientWidth + 2) {
          // Name the innermost element that sticks out. Overflow caused only by
          // hidden popovers (tooltips before they open) is not visible.
          const edge = el.getBoundingClientRect().left + el.clientWidth;
          const sticking = [...el.querySelectorAll('*')].filter((child) => child.getBoundingClientRect().right > edge + 2);
          const visible = sticking.filter((child) => getComputedStyle(child).visibility !== 'hidden');
          if (sticking.length && !visible.length) continue;
          const culprit = visible[visible.length - 1] || null;
          found.push(`${describe(el)} content ${el.scrollWidth}px > box ${el.clientWidth}px${culprit ? ` (sticks out: ${describe(culprit)})` : ''}`);
        }
      }
    }
    return found;
  }, selector);
}

async function assertNoHorizontalOverflow(page, selector) {
  if (page.textSpacing) {
    await page.evaluate((spacing) => {
      if (document.getElementById('ui-smoke-text-spacing')) return;
      const style = document.createElement('style');
      style.id = 'ui-smoke-text-spacing';
      style.textContent = `body, button, input, select, textarea { letter-spacing: ${spacing} !important; }`;
      document.head.appendChild(style);
    }, page.textSpacing);
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  }
  const found = await findOverflow(page, selector);
  if (found.length) problem(page.who, `layout overflow on ${new URL(page.url()).pathname}: ${found.slice(0, 5).join('; ')}`);
}

async function readClipboard(page) {
  return page.evaluate(() => navigator.clipboard.readText());
}

// ---------------------------------------------------------------------------
// Step runner
// ---------------------------------------------------------------------------

const sections = [];
function section(name, fn) {
  sections.push({ name, fn });
}

async function step(name, fn) {
  currentStep = name;
  const started = Date.now();
  console.log(`- ${name}`);
  try {
    await fn();
    console.log(`  ok (${Date.now() - started}ms)`);
  } catch (error) {
    const safe = name.replace(/[^a-z0-9]+/gi, '-').toLowerCase();
    for (const page of pages) {
      if (!page.isClosed()) await shot(page, `FAIL-${safe}-${page.who}`);
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

const state = {};

async function register(page, { name, email, inviteCode }) {
  await page.goto(`${BASE}/login`);
  // A fresh instance opens straight on the registration form.
  const nameInput = page.locator('input[autocomplete="name"]');
  const gotoRegister = page.locator('form button[type="button"]', { hasText: 'Create Account' });
  await nameInput.or(gotoRegister).first().waitFor();
  if (!(await nameInput.isVisible())) await gotoRegister.click();
  await nameInput.fill(name);
  await page.locator('input[type="email"]').fill(email);
  const pw = page.locator('input[autocomplete="new-password"]');
  await pw.nth(0).fill(PASSWORD);
  await pw.nth(1).fill(PASSWORD);
  if (inviteCode) await field(page, 'Invite Code').or(page.locator('label.field', { hasText: /invite/i }).locator('input')).first().fill(inviteCode);
  await page.locator('.auth-page button[type="submit"]').click();
  await waitToast(page, /Registration succeeded/i);
  await page.waitForURL(/\/login/);
}

async function login(page, email, password = PASSWORD) {
  const emailInput = page.locator('input[type="email"], input[autocomplete="username"]').first();
  if (await emailInput.isEditable().catch(() => false)) await emailInput.fill(email);
  await page.locator('input[autocomplete="current-password"]').fill(password);
  await page.locator('.auth-page button[type="submit"]').click();
  await page.waitForURL(/\/vault/, { timeout: 30000 });
  await settle(page);
}

section('auth', async () => {
  const alice = await newPage('alice');
  state.alice = alice;
  await step('register first user (becomes admin)', async () => {
    await register(alice, { name: 'Alice', email: 'alice@example.com' });
  });
  await step('wrong password is rejected with a message', async () => {
    await expecting4xx([{ method: 'POST', path: /^\/identity\/connect\/token$/, status: 400 }], () => allowingErrorToast(async () => {
      await alice.locator('input[autocomplete="current-password"]').fill('not-the-password-123');
      await alice.locator('.auth-page button[type="submit"]').click();
      await alice.locator('.toast-item.error').first().waitFor();
    }));
    assert(alice.url().includes('/login'), 'left the login page after a wrong password');
  });
  await step('password hints are not offered unless the server enables them', async () => {
    const hintButtons = await alice.getByRole('button', { name: 'Show Password Hint' }).count();
    assert(hintButtons === 0, 'login page offers a password hint lookup');
  });
  await step('login', async () => {
    await login(alice, 'alice@example.com');
    await alice.locator('.user-chip', { hasText: 'alice@example.com' }).waitFor();
    await alice.locator('.app-side a[href="/admin"]').waitFor();
  });
  await step('lock and unlock', async () => {
    await alice.locator('.topbar-actions').getByRole('button', { name: 'Lock', exact: true }).click();
    await alice.waitForURL(/\/lock/);
    await alice.locator('input[type="password"]').first().fill(PASSWORD);
    await alice.getByRole('button', { name: 'Unlock', exact: true }).click();
    await alice.waitForURL(/\/vault/);
    await settle(alice);
  });
  await step('reload shows lock screen and unlocks', async () => {
    await alice.reload();
    await alice.getByRole('heading', { name: 'Unlock Vault' }).waitFor();
    await alice.locator('input[type="password"]').first().fill(PASSWORD);
    await alice.getByRole('button', { name: 'Unlock', exact: true }).click();
    await alice.waitForURL(/\/vault/);
    await settle(alice);
  });
  await step('logout and login again', async () => {
    await alice.locator('.topbar-actions').getByRole('button', { name: 'Sign out' }).click();
    await confirmDialog(alice);
    await alice.waitForURL(/\/login/);
    await login(alice, 'alice@example.com');
  });
});

// ---------------------------------------------------------------------------
// Vault items
// ---------------------------------------------------------------------------

function listItem(page, name) {
  return page.locator('.list-col .list-item', { has: page.locator('.list-title-text', { hasText: new RegExp(`^${escapeRegExp(name)}$`) }) });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function selectItem(page, name) {
  await listItem(page, name).locator('.row-main').click();
  await page.locator('.detail-col .detail-title', { hasText: name }).first().waitFor();
}

async function startCreate(page, typeLabel) {
  await page.locator('.desktop-create-trigger').click();
  await page.locator('.create-menu-item', { hasText: new RegExp(`^${escapeRegExp(typeLabel)}$`) }).click();
  await page.locator('.detail-col .detail-title', { hasText: /^New / }).waitFor();
}

async function saveEditor(page) {
  const detail = page.locator('.detail-col');
  await detail.locator('.detail-actions').getByRole('button', { name: 'Confirm', exact: true }).click();
  // Back in view mode once the Edit button reappears.
  await detail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).waitFor({ timeout: 30000 });
  const localError = await page.locator('.local-error:visible').allInnerTexts();
  assert(!localError.length, `editor error: ${localError.join(' ')}`);
}

async function sidebarFilter(page, label) {
  await page.locator('.sidebar .tree-btn', { hasText: new RegExp(`^\\s*${escapeRegExp(label)}\\s*$`) }).first().click();
}

async function listNames(page) {
  return page.locator('.list-col .list-title-text').allInnerTexts();
}

section('vault items', async () => {
  const page = state.alice;
  const detail = page.locator('.detail-col');
  await go(page, '/vault');

  await step('create login with TOTP and website', async () => {
    await startCreate(page, 'Login');
    await field(detail, 'Name').fill('GitHub');
    await field(detail, 'Username').fill('alice-gh');
    await field(detail, 'Password').fill('gh-Pa55word!');
    await field(detail, 'TOTP Secret').fill('JBSWY3DPEHPK3PXP');
    await detail.locator('.website-row input.input, input.input').filter({ hasNot: page.locator('xpath=ancestor::label') }).first().fill('https://github.com/login').catch(async () => {
      await detail.getByRole('button', { name: 'Add Website' }).click();
      await detail.locator('.website-row input.input').first().fill('https://github.com/login');
    });
    await saveEditor(page);
    await listItem(page, 'GitHub').waitFor();
  });

  await step('login detail shows TOTP code and reveals password', async () => {
    await detail.locator('.totp-inline strong', { hasText: /^\d{3} ?\d{3}$/ }).waitFor();
    await detail.getByRole('button', { name: 'Reveal' }).click();
    await detail.getByText('gh-Pa55word!').waitFor();
  });

  await step('edit login name', async () => {
    await detail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).click();
    await field(detail, 'Name').fill('GitHub Work');
    await saveEditor(page);
    await listItem(page, 'GitHub Work').waitFor();
    assert(!(await listNames(page)).includes('GitHub'), 'old name still listed');
  });

  await step('create secure note', async () => {
    await startCreate(page, 'Note');
    await field(detail, 'Name').fill('Wifi Note');
    await field(detail, 'Notes').fill('router password is hunter2');
    await saveEditor(page);
    await detail.getByText('router password is hunter2').waitFor();
  });

  await step('create card', async () => {
    await startCreate(page, 'Card');
    await field(detail, 'Name').fill('Visa Card');
    await field(detail, 'Cardholder Name').fill('Alice Example');
    await field(detail, 'Number').fill('4111111111111111');
    await field(detail, 'Security Code (CVV)').fill('123').catch(() => detail.locator('label.field', { hasText: 'CVV' }).locator('input').fill('123'));
    await saveEditor(page);
    await detail.getByText('Alice Example').waitFor();
  });

  await step('create identity', async () => {
    await startCreate(page, 'Identity');
    await field(detail, 'Name').fill('My Identity');
    await field(detail, 'First Name').fill('Alice');
    await field(detail, 'Last Name').fill('Example');
    await field(detail, 'Email').fill('alice@example.com');
    await saveEditor(page);
    await detail.getByText('Alice Example').waitFor();
  });

  await step('favorite an item and filter favorites', async () => {
    await selectItem(page, 'Wifi Note');
    await detail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).click();
    await detail.getByRole('button', { name: 'Favorite' }).click();
    await saveEditor(page);
    await sidebarFilter(page, 'Favorites');
    await page.waitForFunction(() => document.querySelectorAll('.list-col .list-title-text').length === 1);
    assert((await listNames(page)).join() === 'Wifi Note', `favorites list: ${await listNames(page)}`);
    await sidebarFilter(page, 'All Items');
  });

  await step('search', async () => {
    const search = page.locator('.list-col .search-input');
    await search.fill('visa');
    await page.waitForFunction(() => document.querySelectorAll('.list-col .list-title-text').length === 1);
    assert((await listNames(page)).join() === 'Visa Card', `search result: ${await listNames(page)}`);
    await search.fill('');
    await page.waitForFunction(() => document.querySelectorAll('.list-col .list-title-text').length === 4);
  });

  await step('folders: create, rename, move item, delete', async () => {
    await page.locator('.sidebar .folder-add-btn').click();
    await field(dialog(page), 'Folder Name').fill('Work');
    await confirmDialog(page, 'Create');
    await page.locator('.sidebar .folder-row', { hasText: 'Work' }).waitFor();

    await page.locator('.sidebar .folder-row', { hasText: 'Work' }).locator('.folder-edit-btn').click();
    await field(dialog(page), 'Folder Name').fill('Office');
    await confirmDialog(page, 'Save');
    await page.locator('.sidebar .folder-row', { hasText: 'Office' }).waitFor();

    await listItem(page, 'GitHub Work').locator('.row-check').check();
    await page.locator('.list-col').getByRole('button', { name: 'Move', exact: true }).click();
    await dialog(page).locator('select').selectOption({ label: 'Office' });
    await confirmDialog(page, 'Move');
    await page.locator('.sidebar .folder-row', { hasText: 'Office' }).locator('.tree-btn').click();
    await page.waitForFunction(() => document.querySelectorAll('.list-col .list-title-text').length === 1);
    assert((await listNames(page)).join() === 'GitHub Work', `folder list: ${await listNames(page)}`);

    await page.locator('.sidebar .folder-row', { hasText: 'Office' }).locator('.folder-delete-btn:not(.folder-edit-btn)').click();
    await confirmDialog(page, 'Delete');
    await page.locator('.sidebar .folder-row', { hasText: 'Office' }).waitFor({ state: 'detached' });
    await sidebarFilter(page, 'All Items');
    await listItem(page, 'GitHub Work').waitFor();
  });

  await step('delete item to trash, restore, delete permanently', async () => {
    await selectItem(page, 'My Identity');
    await detail.locator('.detail-actions').getByRole('button', { name: 'Delete', exact: true }).click();
    await confirmDialog(page);
    await listItem(page, 'My Identity').waitFor({ state: 'detached' });
    await sidebarFilter(page, 'Trash');
    await selectItem(page, 'My Identity');
    await detail.getByRole('button', { name: 'Restore' }).click();
    await listItem(page, 'My Identity').waitFor({ state: 'detached' });
    await sidebarFilter(page, 'All Items');
    await selectItem(page, 'My Identity');
    await detail.locator('.detail-actions').getByRole('button', { name: 'Delete', exact: true }).click();
    await confirmDialog(page);
    await sidebarFilter(page, 'Trash');
    await selectItem(page, 'My Identity');
    await detail.getByRole('button', { name: 'Delete Permanently' }).click();
    await confirmDialog(page);
    await listItem(page, 'My Identity').waitFor({ state: 'detached' });
    await sidebarFilter(page, 'All Items');
  });

  await step('attachment upload and download', async () => {
    await selectItem(page, 'Visa Card');
    await detail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).click();
    const content = `attachment body ${Date.now()}\n`;
    await detail.locator('input.attachment-file-input').setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from(content) });
    await detail.getByText('notes.txt').waitFor();
    await saveEditor(page);
    const row = detail.locator('.attachment-row', { hasText: 'notes.txt' });
    await row.waitFor();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      row.getByRole('button', { name: 'Download' }).click(),
    ]);
    const file = await download.path();
    assert(readFileSync(file, 'utf8') === content, 'downloaded attachment content differs');
    assert(download.suggestedFilename() === 'notes.txt', `download name ${download.suggestedFilename()}`);
  });

  await step('verification code page', async () => {
    await go(page, '/vault/totp');
    await page.getByText('GitHub Work').first().waitFor();
    await page.locator('main').getByText(/^\d{3} ?\d{3}$/).first().waitFor();
  });
});

// ---------------------------------------------------------------------------
// Sends
// ---------------------------------------------------------------------------

async function openPublicSend(url, who) {
  const page = await newPage(who);
  await page.goto(url);
  return page;
}

section('sends', async () => {
  const page = state.alice;
  const detail = page.locator('.detail-col');
  await go(page, '/sends');

  await step('create password-protected text send', async () => {
    await page.locator('.list-col').getByRole('button', { name: 'Add' }).click();
    await field(detail, 'Name').fill('Door code');
    await field(detail, 'Text').fill('the door code is 4711');
    await field(detail, 'Password').fill('send-secret');
    await detail.getByRole('button', { name: 'Save', exact: true }).click();
    await detail.locator('.detail-title', { hasText: 'Door code' }).waitFor();
    await detail.getByText('the door code is 4711').waitFor();
  });

  await step('open text send link in a fresh browser and reveal it', async () => {
    await detail.getByRole('button', { name: 'Copy Link' }).click();
    const url = await readClipboard(page);
    assert(url.startsWith(`${BASE}/`) && url.includes('#'), `send url ${url}`);
    const visitor = await openPublicSend(url, 'send-visitor');
    await expecting4xx([{ method: 'POST', path: /^\/api\/sends\/access\//, status: 401 }], async () => {
      await visitor.locator('input[type="password"]').fill('send-secret');
      await visitor.getByRole('button', { name: 'Unlock Send' }).click();
      await visitor.getByText('the door code is 4711').waitFor();
    });
    await visitor.context().close();
  });

  await step('create file send and download it anonymously', async () => {
    const content = `file send payload ${Date.now()}\n`;
    await page.locator('.list-col').getByRole('button', { name: 'Add' }).click();
    await field(detail, 'Name').fill('Shared file');
    await detail.locator('.send-options label', { hasText: 'File' }).locator('input[type="radio"]').check();
    await detail.locator('input[type="file"]').setInputFiles({ name: 'payload.txt', mimeType: 'text/plain', buffer: Buffer.from(content) });
    await detail.getByRole('button', { name: 'Save', exact: true }).click();
    await detail.locator('.detail-title', { hasText: 'Shared file' }).waitFor({ timeout: 30000 });
    await detail.getByText('payload.txt').waitFor();
    await detail.getByRole('button', { name: 'Copy Link' }).click();
    const url = await readClipboard(page);
    const visitor = await openPublicSend(url, 'send-visitor');
    await visitor.getByText('payload.txt').waitFor();
    const [download] = await Promise.all([
      visitor.waitForEvent('download'),
      visitor.getByRole('button', { name: 'Download' }).click(),
    ]);
    assert(readFileSync(await download.path(), 'utf8') === content, 'file send content differs');
    await visitor.context().close();
  });

  await step('edit and delete a send', async () => {
    await page.locator('.list-col .list-item', { hasText: 'Door code' }).locator('.row-main').click();
    await detail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).click();
    await field(detail, 'Name').fill('Door code (old)');
    await detail.getByRole('button', { name: 'Save', exact: true }).click();
    await page.locator('.list-col .list-item', { hasText: 'Door code (old)' }).waitFor();
    await detail.locator('.detail-actions').getByRole('button', { name: 'Delete', exact: true }).click();
    await page.locator('.list-col .list-item', { hasText: 'Door code (old)' }).waitFor({ state: 'detached' });
  });
});

// ---------------------------------------------------------------------------
// Tools: generator, import/export
// ---------------------------------------------------------------------------

section('tools', async () => {
  const page = state.alice;

  await step('password generator', async () => {
    await go(page, '/generator');
    const output = page.locator('.generator-value');
    await output.waitFor();
    const first = (await output.innerText()).trim();
    assert(first.length >= 5, `generated value "${first}"`);
    await page.locator('.generator-page').getByRole('button', { name: /Regenerate|Generate/ }).first().click();
    await page.waitForFunction((prev) => document.querySelector('.generator-value')?.textContent?.trim() !== prev, first);
    for (const tab of await page.locator('.generator-mode-tabs [role="tab"]').all()) {
      await tab.click();
      await page.waitForFunction((el) => el.getAttribute('aria-selected') === 'true', await tab.elementHandle());
      await page.locator('.generator-value, .generator-page code, .generator-page pre').first().waitFor();
      await assertNoHorizontalOverflow(page, '.generator-page');
    }
    await page.locator('.generator-mode-tabs [role="tab"]').first().click();
  });

  await step('password security report', async () => {
    await go(page, '/security/password-health');
    // Starting the check calls the external breach API, so only the page itself is exercised.
    await page.locator('main').getByRole('button', { name: 'Start check' }).waitFor();
  });

  await step('import Bitwarden JSON', async () => {
    await go(page, '/backup/import-export');
    const panel = page.locator('.import-export-panel').first();
    await field(panel, 'Format').selectOption('bitwarden_json');
    const data = {
      encrypted: false,
      folders: [{ id: 'f0000000-0000-4000-8000-000000000001', name: 'Imported Folder' }],
      items: [
        {
          id: 'i0000000-0000-4000-8000-000000000001', type: 1, name: 'Imported Login', folderId: 'f0000000-0000-4000-8000-000000000001', favorite: false,
          notes: null, reprompt: 0,
          login: { username: 'imported-user', password: 'imported-pass', totp: null, uris: [{ uri: 'https://example.org', match: null }] },
        },
        { id: 'i0000000-0000-4000-8000-000000000002', type: 2, name: 'Imported Note', folderId: null, favorite: true, notes: 'imported secret note', reprompt: 0, secureNote: { type: 0 } },
      ],
    };
    await panel.locator('input[type="file"]').setInputFiles({ name: 'bitwarden.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(data)) });
    await panel.getByRole('button', { name: 'Import', exact: true }).click();
    const summary = page.locator('.import-summary-dialog');
    await summary.waitFor({ timeout: 30000 });
    assert(/2/.test(await summary.locator('.dialog-message').first().innerText()), 'import summary count');
    await summary.getByRole('button').first().click();
    await go(page, '/vault');
    await listItem(page, 'Imported Login').waitFor();
    await page.locator('.sidebar .folder-row', { hasText: 'Imported Folder' }).waitFor();
  });

  async function exportAs(format, verify) {
    await go(page, '/backup/import-export');
    const panel = page.locator('.import-export-panel').nth(1);
    await field(panel, 'Format').selectOption(format);
    await panel.getByRole('button', { name: 'Export', exact: true }).click();
    await field(dialog(page), 'Master Password').fill(PASSWORD);
    const [download] = await Promise.all([page.waitForEvent('download', { timeout: 60000 }), confirmDialog(page)]);
    await verify(readFileSync(await download.path()), download.suggestedFilename());
  }

  await step('export plain Bitwarden JSON', async () => {
    await exportAs('bitwarden_json', async (bytes) => {
      const json = JSON.parse(bytes.toString('utf8'));
      const names = json.items.map((item) => item.name).sort();
      for (const expected of ['GitHub Work', 'Imported Login', 'Imported Note', 'Visa Card', 'Wifi Note']) {
        assert(names.includes(expected), `export is missing ${expected}: ${names}`);
      }
      assert(json.folders.some((folder) => folder.name === 'Imported Folder'), 'export is missing folder');
    });
  });

  await step('export encrypted JSON', async () => {
    await exportAs('bitwarden_encrypted_json', async (bytes) => {
      const json = JSON.parse(bytes.toString('utf8'));
      assert(json.encrypted === true && json.items.length >= 5, 'encrypted export shape');
    });
  });

  await step('export zip with attachments', async () => {
    await exportAs('bitwarden_json_zip', async (bytes, name) => {
      assert(bytes.subarray(0, 2).toString('latin1') === 'PK', `zip export ${name} is not a zip`);
    });
  });
});

// ---------------------------------------------------------------------------
// Settings and system management
// ---------------------------------------------------------------------------

async function settingsTab(page, label) {
  await page.locator('.settings-category-tabs .settings-category-tab', { hasText: label }).click();
}

async function masterPasswordPrompt(page) {
  await field(dialog(page), 'Master Password').fill(PASSWORD);
  await confirmDialog(page);
}

section('settings', async () => {
  const page = state.alice;

  await step('account settings tabs', async () => {
    await go(page, '/settings/account');
    for (const label of ['Appearance', 'Session Timeout', 'Master Password', 'Two-step Login', 'Keys']) {
      await settingsTab(page, label);
      await page.locator('.settings-category-panel .settings-section-stack, .settings-category-panel section').first().waitFor();
    }
  });

  await step('two-step login: authenticator setup opens', async () => {
    await settingsTab(page, 'Two-step Login');
    await page.locator('.settings-category-panel .card, .settings-category-panel section', { hasText: 'Authenticator App' })
      .getByRole('button', { name: 'Manage' }).first().click();
    await masterPasswordPrompt(page);
    const setup = dialog(page);
    await setup.locator('.totp-qr img').waitFor();
    assert((await setup.locator('.totp-secret-input').inputValue()).length >= 16, 'TOTP secret missing');
    await setup.locator('.dialog-close-btn').click();
    await setup.waitFor({ state: 'detached' }).catch(() => {});
  });

  await step('device management', async () => {
    await go(page, '/settings/security/device-management');
    await page.locator('main').getByText(/Chrome|Browser|Web/i).first().waitFor();
  });

  await step('domain rules: add custom rule and save', async () => {
    await go(page, '/settings/domain-rules');
    const custom = page.locator('.domain-rules-custom');
    await custom.getByRole('button', { name: 'Add', exact: true }).click();
    const inputs = custom.locator('.domain-rule-new-row input.domain-rule-inline-input');
    await inputs.nth(0).fill('example-one.test');
    await inputs.nth(1).fill('example-two.test');
    await custom.locator('.domain-rule-new-row').getByRole('button', { name: 'Confirm' }).click();
    await page.locator('.domain-rules-toolbar').getByRole('button', { name: 'Save', exact: true }).click();
    await waitToast(page, /saved/i);
    await custom.getByText('example-two.test').waitFor();
  });

  await step('backup center opens', async () => {
    await go(page, '/backup');
    await page.locator('.backup-grid').waitFor();
    // Let the page finish its initial requests before moving on.
    await settle(page);
  });

  await step('backup center: export local backup', async () => {
    await page.locator('.backup-grid').getByRole('button', { name: 'Export Backup' }).click();
    const [download] = await Promise.all([
      page.waitForEvent('download', { timeout: 60000 }),
      (async () => {
        await field(dialog(page), 'Master Password').fill(PASSWORD);
        await confirmDialog(page);
      })(),
    ]);
    const bytes = readFileSync(await download.path());
    assert(bytes.subarray(0, 2).toString('latin1') === 'PK', `backup ${download.suggestedFilename()} is not a zip`);
  });

  await step('log center opens', async () => {
    await go(page, '/logs');
    await page.locator('.log-center-page').waitFor();
    await settle(page);
  });
});

section('admin and second user', async () => {
  const page = state.alice;

  await step('admin users list', async () => {
    await go(page, '/admin');
    await page.locator('main table').first().getByText('alice@example.com').waitFor();
  });

  await step('mint invite code', async () => {
    await page.getByRole('button', { name: 'Create Timed Invite' }).click();
    await masterPasswordPrompt(page);
    const row = page.locator('main table').nth(1).locator('tbody tr', { has: page.getByRole('button', { name: 'Copy Link' }) }).first();
    await row.waitFor();
    state.inviteCode = (await row.locator('td').first().innerText()).trim();
    await row.getByRole('button', { name: 'Copy Link' }).click();
    state.inviteLink = await readClipboard(page);
    assert(state.inviteLink.includes(state.inviteCode), `invite link ${state.inviteLink}`);
  });

  await step('register second user through the invite link', async () => {
    const bob = await newPage('bob');
    state.bob = bob;
    await bob.goto(state.inviteLink);
    await bob.locator('input[autocomplete="name"]').or(bob.locator('form button[type="button"]', { hasText: 'Create Account' })).first().waitFor();
    if (!(await bob.locator('input[autocomplete="name"]').isVisible())) {
      await bob.locator('form button[type="button"]', { hasText: 'Create Account' }).click();
    }
    const inviteInput = bob.locator('label.field', { hasText: /invite/i }).locator('input');
    assert((await inviteInput.inputValue()) === state.inviteCode, 'invite code not prefilled from link');
    await bob.locator('input[autocomplete="name"]').fill('Bob');
    await bob.locator('input[type="email"]').fill('bob@example.com');
    const pw = bob.locator('input[autocomplete="new-password"]');
    await pw.nth(0).fill(PASSWORD);
    await pw.nth(1).fill(PASSWORD);
    await bob.locator('.auth-page button[type="submit"]').click();
    await waitToast(bob, /Registration succeeded/i);
    await login(bob, 'bob@example.com');
    assert(!(await bob.locator('.app-side a[href="/admin"]').isVisible()), 'second user sees the admin menu');
  });

  await step('admin sees second user and used invite', async () => {
    await page.locator('main').getByRole('button', { name: 'Refresh' }).first().click();
    await page.locator('main table').first().getByText('bob@example.com').waitFor();
  });
});

// ---------------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------------

async function syncVault(page) {
  await go(page, '/vault');
  await page.locator('.list-col').getByRole('button', { name: 'Sync Vault' }).click();
  await settle(page);
}

section('organizations', async () => {
  const alice = state.alice;
  const bob = state.bob;
  const aliceDetail = alice.locator('.detail-col');
  const bobDetail = bob.locator('.detail-col');

  await step('create organization', async () => {
    await go(alice, '/organizations');
    await alice.locator('main').getByRole('button', { name: 'New organization' }).click();
    await field(dialog(alice), 'Organization name').fill('Family');
    await confirmDialog(alice);
    await alice.locator('.org-switch-btn', { hasText: 'Family' }).waitFor();
  });

  await step('invite second user', async () => {
    await alice.locator('main').getByRole('button', { name: 'Invite member' }).click();
    const invite = dialog(alice);
    await invite.locator('input[placeholder="name@example.com"]').fill('bob@example.com');
    await invite.locator('.org-access-row select').first().selectOption('edit');
    await confirmDialog(alice);
    await alice.locator('main table tr', { hasText: 'bob@example.com' }).getByText('Invited').waitFor();
  });

  await step('second user accepts', async () => {
    await go(bob, '/organizations');
    await bob.locator('main').getByRole('button', { name: 'Accept' }).click();
    await bob.locator('.org-fingerprint-note strong').waitFor();
    state.bobFingerprint = (await bob.locator('.org-fingerprint-note strong').innerText()).trim();
  });

  await step('owner confirms member after checking fingerprint', async () => {
    await alice.locator('main').getByRole('button', { name: 'Refresh' }).first().click();
    const row = alice.locator('main table tr', { hasText: 'bob@example.com' });
    await row.getByRole('button', { name: 'Confirm' }).click();
    const shown = (await dialog(alice).locator('.org-fingerprint-box strong').innerText()).trim();
    assert(shown && shown === state.bobFingerprint, `fingerprint mismatch: "${shown}" vs "${state.bobFingerprint}"`);
    await confirmDialog(alice);
    await row.getByText('Confirmed').waitFor();
  });

  await step('create collection shared with the member', async () => {
    await alice.locator('.org-tab', { hasText: 'Collections' }).click();
    await alice.locator('main').getByRole('button', { name: 'New collection' }).click();
    const editor = dialog(alice);
    await field(editor, 'Name').fill('Shared Docs');
    await editor.locator('.org-access-row', { hasText: 'bob@example.com' }).locator('select').selectOption('edit');
    await confirmDialog(alice);
    await alice.locator('main table tr', { hasText: 'Shared Docs' }).waitFor();
  });

  await step('create organization item', async () => {
    await go(alice, '/vault');
    await startCreate(alice, 'Login');
    await field(aliceDetail, 'Name').fill('Shared Wifi');
    await field(aliceDetail, 'Password').fill('family-wifi-pass');
    await field(aliceDetail, 'Owner').selectOption({ label: 'Family' });
    await aliceDetail.locator('.org-collection-checklist label', { hasText: 'Shared Docs' }).locator('input').check();
    await saveEditor(alice);
    await listItem(alice, 'Shared Wifi').waitFor();
  });

  await step('move personal item with attachment into organization', async () => {
    await selectItem(alice, 'Visa Card');
    await aliceDetail.getByRole('button', { name: 'Move to organization' }).click();
    const move = dialog(alice);
    await move.locator('.org-collection-checklist label', { hasText: 'Shared Docs' }).locator('input').check();
    await confirmDialog(alice, 'Move');
    await aliceDetail.locator('.org-panel').getByText('Family').waitFor({ timeout: 30000 });
  });

  await step('member sees and decrypts both items and the attachment', async () => {
    await syncVault(bob);
    await selectItem(bob, 'Shared Wifi');
    await bobDetail.getByRole('button', { name: 'Reveal' }).click();
    await bobDetail.getByText('family-wifi-pass').waitFor();
    await bobDetail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).waitFor();
    await selectItem(bob, 'Visa Card');
    await bobDetail.getByText('Alice Example').waitFor();
    const row = bobDetail.locator('.attachment-row', { hasText: 'notes.txt' });
    const [download] = await Promise.all([bob.waitForEvent('download'), row.getByRole('button', { name: 'Download' }).click()]);
    assert(readFileSync(await download.path(), 'utf8').startsWith('attachment body'), 'shared attachment content');
  });

  await step('member with edit access can edit', async () => {
    await selectItem(bob, 'Shared Wifi');
    await bobDetail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).click();
    await field(bobDetail, 'Username').fill('edited-by-bob');
    await saveEditor(bob);
    await bobDetail.getByText('edited-by-bob').waitFor();
  });

  await step('restrict collection to read-only', async () => {
    await go(alice, '/organizations');
    await alice.locator('.org-tab', { hasText: 'Collections' }).click();
    await alice.locator('main table tr', { hasText: 'Shared Docs' }).getByRole('button', { name: 'Edit' }).click();
    await dialog(alice).locator('.org-access-row', { hasText: 'bob@example.com' }).locator('select').selectOption('view');
    await confirmDialog(alice);
    await waitToast(alice, /saved/i);
  });

  await step('member can no longer edit', async () => {
    await syncVault(bob);
    await selectItem(bob, 'Shared Wifi');
    await bobDetail.getByText('edited-by-bob').waitFor();
    // Wait for the new permission to render; the panel itself was already there.
    await bobDetail.locator('.org-panel', { hasText: 'You can view this item but not change it' }).waitFor();
    assert(!(await bobDetail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true }).isVisible()), 'read-only member still sees Edit');
    assert(!(await bobDetail.locator('.detail-actions').getByRole('button', { name: 'Delete', exact: true }).isVisible()), 'read-only member still sees Delete');
  });
});

// ---------------------------------------------------------------------------
// Chinese UI: no raw i18n keys
// ---------------------------------------------------------------------------

const MAIN_PAGES = ['/vault', '/sends', '/organizations', '/vault/totp', '/generator', '/security/password-health', '/backup/import-export',
  '/settings/account', '/settings/security/device-management', '/settings/domain-rules', '/backup', '/admin', '/logs'];

async function unlock(page) {
  await page.locator('.auth-page input[type="password"]').first().fill(PASSWORD);
  await page.locator('.auth-page button[type="submit"]').click();
  await page.locator('.app-shell').waitFor({ timeout: 30000 });
  await settle(page);
}

async function setLanguage(page, locale) {
  await go(page, '/settings/account');
  await page.locator('.settings-category-tabs .settings-category-tab').first().click();
  await Promise.all([
    page.waitForEvent('load'),
    page.locator('.settings-category-panel select').nth(1).selectOption(locale),
  ]);
  await unlock(page);
}

section('i18n', async () => {
  const page = state.alice;
  await step('switch to Simplified Chinese', async () => {
    await setLanguage(page, 'zh-CN');
    await page.locator('.app-side').getByText('密码库').first().waitFor();
  });
  for (const path of MAIN_PAGES) {
    await step(`no raw i18n keys on ${path}`, async () => {
      await go(page, path);
      if (path === '/vault') await selectItem(page, 'GitHub Work');
      const text = await page.locator('body').innerText();
      const raw = [...new Set(text.match(/\b(txt|nav)_[a-z0-9_]{3,}\b/g) || [])];
      assert(!raw.length, `raw i18n keys on ${path}: ${raw.join(', ')}`);
    });
  }
  await step('switch back to English', async () => {
    await setLanguage(page, 'en');
    await page.locator('.app-side').getByText('Vault').first().waitFor();
  });
});

// ---------------------------------------------------------------------------
// Mobile layout
// ---------------------------------------------------------------------------

section('mobile', async () => {
  const phone = await newPage('alice-mobile', { viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true });
  // Fonts differ between machines (CI runners render noticeably wider than
  // the Playwright image); overflow checks on the phone widen text a little
  // so layouts that only just fit are caught everywhere.
  phone.textSpacing = env.UI_MOBILE_LETTER_SPACING || '0.04em';
  await step('login on a phone viewport', async () => {
    await phone.goto(`${BASE}/login`);
    await login(phone, 'alice@example.com');
  });
  for (const path of MAIN_PAGES) {
    await step(`no horizontal overflow on ${path}`, async () => {
      await go(phone, path);
      await assertNoHorizontalOverflow(phone, '.app-shell');
    });
  }
  await step('open an item on the phone', async () => {
    await go(phone, '/vault');
    await listItem(phone, 'GitHub Work').locator('.row-main').click();
    await phone.locator('.detail-col.open .detail-title', { hasText: 'GitHub Work' }).waitFor();
    await assertNoHorizontalOverflow(phone, '.app-shell');
  });
  await step('create an item on the phone', async () => {
    await phone.locator('.detail-col.open').getByRole('button', { name: 'Back' }).click();
    await phone.locator('.mobile-fab-trigger').click();
    await phone.locator('.create-menu-item', { hasText: /^Note$/ }).click();
    const sheet = phone.locator('.detail-col.open');
    await field(sheet, 'Name').fill('Phone note');
    await field(sheet, 'Notes').fill('written on a phone');
    await sheet.locator('.detail-actions').getByRole('button', { name: 'Confirm', exact: true }).click();
    await listItem(phone, 'Phone note').locator('.row-main').click();
    await phone.locator('.detail-col.open').getByText('written on a phone').waitFor();
    await assertNoHorizontalOverflow(phone, '.app-shell');
  });
  await step('tab bar navigation on the phone', async () => {
    for (const label of ['Verification Code', 'Generator', 'Sends', 'Settings', 'My Vault']) {
      await phone.locator('.mobile-tabbar .mobile-tab', { hasText: label }).click();
      await settle(phone);
      await assertNoHorizontalOverflow(phone, '.app-shell');
    }
  });
});

// ---------------------------------------------------------------------------
// More vault features
// ---------------------------------------------------------------------------

section('vault extras', async () => {
  const page = state.alice;
  const detail = page.locator('.detail-col');
  const editButton = detail.locator('.detail-actions').getByRole('button', { name: 'Edit', exact: true });

  await step('create bank account, driver license, passport and SSH key', async () => {
    await go(page, '/vault');
    await startCreate(page, 'Bank Account');
    await field(detail, 'Name').fill('Savings');
    await field(detail, 'Bank Name').fill('Example Bank');
    await saveEditor(page);
    await detail.getByText('Example Bank').waitFor();

    await startCreate(page, 'Driver License');
    await field(detail, 'Name').fill('License');
    await field(detail, 'License Number').fill('DL-12345');
    await saveEditor(page);
    await detail.getByText('DL-12345').waitFor();

    await startCreate(page, 'Passport');
    await field(detail, 'Name').fill('Passport');
    await field(detail, 'Passport Number').fill('P-998877');
    await saveEditor(page);
    await detail.getByText('P-998877').waitFor();

    await startCreate(page, 'SSH Key');
    await field(detail, 'Name').fill('Deploy key');
    await page.waitForFunction(() => /ssh-/.test([...document.querySelectorAll('.detail-col textarea')].map((el) => el.value).join(' ')));
    await saveEditor(page);
    await detail.getByText(/^SHA256:/).first().waitFor();
  });

  await step('custom fields and password history', async () => {
    await selectItem(page, 'GitHub Work');
    await editButton.click();
    await detail.getByRole('button', { name: 'Add Field' }).click();
    const add = dialog(page);
    await field(add, 'Field Label').fill('Recovery email');
    await add.locator('textarea, input:not([type="checkbox"])').last().fill('recovery@example.com');
    await confirmDialog(page, 'Add');
    await field(detail, 'Password').fill('gh-Pa55word-2');
    await saveEditor(page);
    await detail.getByText('Recovery email').waitFor();
    await detail.getByRole('button', { name: 'Password History' }).click();
    await page.locator('.password-history-dialog').getByText('gh-Pa55word!').waitFor();
    await page.locator('.password-history-dialog').getByRole('button', { name: 'Close' }).last().click();
  });

  await step('master password reprompt', async () => {
    await selectItem(page, 'Savings');
    await editButton.click();
    await detail.locator('label.check-line', { hasText: 'Master password reprompt' }).locator('input').check();
    await detail.locator('.detail-actions').getByRole('button', { name: 'Confirm', exact: true }).click();
    await detail.getByRole('button', { name: 'Unlock Details' }).or(editButton).first().waitFor();
    await selectItem(page, 'Wifi Note');
    // Details (and the title) stay hidden until the master password is re-entered.
    await listItem(page, 'Savings').locator('.row-main').click();
    await detail.getByRole('button', { name: 'Unlock Details' }).click();
    await field(dialog(page), 'Master Password').fill(PASSWORD);
    await confirmDialog(page);
    await detail.getByText('Example Bank').waitFor();
  });

  await step('archive and unarchive', async () => {
    await selectItem(page, 'Passport');
    await detail.locator('.detail-actions').getByRole('button', { name: 'Archive', exact: true }).click();
    await confirmDialog(page, 'Archive');
    await listItem(page, 'Passport').waitFor({ state: 'detached' });
    await sidebarFilter(page, 'Archive');
    await selectItem(page, 'Passport');
    await detail.locator('.detail-actions').getByRole('button', { name: 'Unarchive' }).click();
    await listItem(page, 'Passport').waitFor({ state: 'detached' });
    await sidebarFilter(page, 'All Items');
    await listItem(page, 'Passport').waitFor();
  });

  await step('duplicates view', async () => {
    await sidebarFilter(page, 'Duplicates');
    await page.locator('.list-col').waitFor();
    await sidebarFilter(page, 'All Items');
  });

  await step('bulk select and delete', async () => {
    await listItem(page, 'License').locator('.row-check').check();
    await listItem(page, 'Deploy key').locator('.row-check').check();
    await page.locator('.list-col .list-head').getByRole('button', { name: 'Delete', exact: true }).click();
    await confirmDialog(page);
    await listItem(page, 'License').waitFor({ state: 'detached' });
    await listItem(page, 'Deploy key').waitFor({ state: 'detached' });
    await sidebarFilter(page, 'Trash');
    await listItem(page, 'Deploy key').waitFor();
    await sidebarFilter(page, 'All Items');
  });

  await step('type filters', async () => {
    for (const label of ['Login', 'Card', 'Bank Account', 'Identity', 'Driver License', 'Passport', 'Note', 'SSH Key']) {
      await sidebarFilter(page, label);
    }
    await sidebarFilter(page, 'Note');
    await page.waitForFunction(() => document.querySelectorAll('.list-col .list-title-text').length === 2);
    assert((await listNames(page)).every((name) => ['Wifi Note', 'Imported Note'].includes(name)), `note filter: ${await listNames(page)}`);
    await sidebarFilter(page, 'All Items');
  });

  await step('theme toggle', async () => {
    const toggle = page.locator('.topbar-actions > .theme-switch-wrap .theme-switch');
    const themeState = () => page.evaluate(() => `${document.documentElement.className}|${JSON.stringify(document.documentElement.dataset)}|${document.body.className}`);
    const before = await themeState();
    await toggle.click();
    await page.waitForFunction((prev) => `${document.documentElement.className}|${JSON.stringify(document.documentElement.dataset)}|${document.body.className}` !== prev, before);
    await shot(page, 'dark-theme-vault');
    await toggle.click();
    await page.waitForFunction((prev) => `${document.documentElement.className}|${JSON.stringify(document.documentElement.dataset)}|${document.body.className}` === prev, before);
    assert((await themeState()) === before, 'theme did not toggle back');
  });

  await step('keys: view API key and recovery code', async () => {
    await go(page, '/settings/account');
    await settingsTab(page, 'Keys');
    await page.locator('.settings-category-panel').getByRole('button', { name: 'View API Key' }).click();
    await masterPasswordPrompt(page);
    await page.waitForFunction(() => [...document.querySelectorAll('.dialog-card.open input')].some((input) => /^user\.[0-9a-f-]{36}$/.test(input.value)));
    await dialog(page).getByRole('button', { name: 'Close', exact: true }).last().click();
    await settingsTab(page, 'Two-step Login');
    await page.locator('.settings-category-panel').getByRole('button', { name: 'View Recovery Code' }).click();
    await masterPasswordPrompt(page);
    await dialog(page).getByRole('heading', { name: 'Two-step login Recovery Code' }).waitFor();
    await dialog(page).locator('.dialog-close-btn').click();
  });

  await step('session timeout setting', async () => {
    await settingsTab(page, 'Session Timeout');
    const selects = page.locator('.settings-category-panel select');
    await selects.nth(0).selectOption({ index: 2 });
    await selects.nth(1).selectOption('lock');
  });
});

// ---------------------------------------------------------------------------
// Account and organization lifecycle (runs last: changes passwords, deletes data)
// ---------------------------------------------------------------------------

section('lifecycle', async () => {
  const alice = state.alice;
  const bob = state.bob;
  const NEW_PASSWORD = 'Another-Correct-Horse-7';

  await step('member changes master password and logs back in', async () => {
    await go(bob, '/settings/account');
    await settingsTab(bob, 'Master Password');
    const panel = bob.locator('.settings-category-panel');
    await field(panel, 'Current Password').fill(PASSWORD);
    await field(panel, 'New Password').fill(NEW_PASSWORD);
    await field(panel, 'Confirm Password').fill(NEW_PASSWORD);
    await panel.getByRole('button', { name: 'Change Password' }).click();
    await confirmDialog(bob);
    await bob.waitForURL(/\/login/, { timeout: 30000 });
    await login(bob, 'bob@example.com', NEW_PASSWORD);
    await selectItem(bob, 'Shared Wifi');
    await bob.locator('.detail-col').getByText('edited-by-bob').waitFor();
  });

  await step('owner creates and deletes a collection', async () => {
    await go(alice, '/organizations');
    await alice.locator('.org-tab', { hasText: 'Collections' }).click();
    await alice.locator('main').getByRole('button', { name: 'New collection' }).click();
    await field(dialog(alice), 'Name').fill('Temporary');
    await confirmDialog(alice);
    const row = alice.locator('main table tr', { hasText: 'Temporary' });
    await row.getByRole('button', { name: 'Delete' }).click();
    await confirmDialog(alice);
    await row.waitFor({ state: 'detached' });
  });

  await step('owner edits member role', async () => {
    await alice.locator('.org-tab', { hasText: 'Members' }).click();
    const row = alice.locator('main table tr', { hasText: 'bob@example.com' });
    await row.getByRole('button', { name: 'Edit' }).click();
    await field(dialog(alice), 'Role').selectOption({ label: 'Admin' });
    await confirmDialog(alice);
    await row.getByText('Admin').waitFor();
  });

  await step('owner deletes organization', async () => {
    await alice.locator('.org-tab', { hasText: 'Settings' }).click();
    await alice.locator('main').getByRole('button', { name: 'Delete organization' }).click();
    await field(dialog(alice), 'Master Password').fill(PASSWORD);
    await confirmDialog(alice);
    await alice.locator('.org-switch-btn', { hasText: 'Family' }).waitFor({ state: 'detached' });
    await syncVault(bob);
    await listItem(bob, 'Shared Wifi').waitFor({ state: 'detached' });
  });
});

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

let exitCode = 0;
try {
  if (!env.UI_BASE_URL) {
    await resetDatabase();
    await ensureBucket();
    await startServer();
  }
  for (const { name, fn } of sections) {
    if (ONLY.length && !ONLY.includes(name) && name !== 'auth') continue;
    console.log(`\n== ${name}`);
    currentStep = `${name}`;
    try {
      await fn();
    } catch (error) {
      failures.push(`[${currentStep}] ${error?.stack || error}`);
      console.log(`  FAILED: ${String(error?.message || error).split('\n')[0]}`);
      if (name === 'auth') break;
    }
  }
} catch (error) {
  failures.push(`[setup] ${error?.stack || error}`);
} finally {
  await browser.close().catch(() => {});
  stopServer();
}

console.log('\n==================== UI smoke summary ====================');
if (failures.length) {
  exitCode = 1;
  console.log(`${failures.length} failed step(s):`);
  for (const failure of failures) console.log(`  ${failure.split('\n').slice(0, 4).join('\n    ')}`);
}
if (problems.length) {
  exitCode = 1;
  console.log(`${problems.length} problem(s) observed:`);
  for (const entry of problems) console.log(`  ${entry}`);
}
if (!exitCode) console.log('all flows passed with no page errors, console errors, error toasts or unexpected HTTP errors');
console.log(`artifacts: ${ARTIFACTS}`);
process.exit(exitCode);
