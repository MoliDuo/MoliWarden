// Driver for the official Bitwarden CLI (@bitwarden/cli) in end-to-end tests.
//
// The CLI is not a project dependency (it would bloat Vercel installs). It is
// resolved from, in order:
//   BW_CLI                     path to a `bw` executable
//   BW_CLI_CACHE_DIR (default ~/.cache/moliwarden-bw-cli), installed there on
//                              first use with `npm install @bitwarden/cli@BW_CLI_VERSION`
// Official clients refuse plain-HTTP servers, so tests serve HTTPS with a
// throwaway self-signed certificate trusted via NODE_EXTRA_CA_CERTS.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

export const BW_CLI_VERSION = process.env.BW_CLI_VERSION || '2026.9.0';

export function resolveBwCli(): string {
  if (process.env.BW_CLI) return process.env.BW_CLI;
  const cacheDir = process.env.BW_CLI_CACHE_DIR || join(homedir(), '.cache', 'moliwarden-bw-cli');
  const bin = join(cacheDir, 'node_modules', '.bin', process.platform === 'win32' ? 'bw.cmd' : 'bw');
  const installedVersion = (() => {
    try {
      return JSON.parse(readFileSync(join(cacheDir, 'node_modules', '@bitwarden', 'cli', 'package.json'), 'utf8')).version;
    } catch {
      return null;
    }
  })();
  if (!existsSync(bin) || installedVersion !== BW_CLI_VERSION) {
    mkdirSync(cacheDir, { recursive: true });
    execFileSync('npm', ['install', '--no-save', '--no-audit', '--no-fund', '--prefix', cacheDir, `@bitwarden/cli@${BW_CLI_VERSION}`], {
      stdio: 'inherit',
    });
  }
  return bin;
}

export interface TlsMaterial {
  key: Buffer;
  cert: Buffer;
  certPath: string;
  dir: string;
}

export function createSelfSignedCert(): TlsMaterial {
  const dir = mkdtempSync(join(tmpdir(), 'mw-bw-tls-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync(
    'openssl',
    ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '2',
      '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'],
    { stdio: 'ignore' }
  );
  return { key: readFileSync(keyPath), cert: readFileSync(certPath), certPath, dir };
}

export interface BwResult {
  code: number;
  stdout: string;
  stderr: string;
}

export function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
}

// One official CLI "installation": its own app-data dir, so several users
// can be logged in side by side.
export class BwCli {
  readonly appDataDir: string;
  session: string | null = null;

  constructor(
    readonly bin: string,
    readonly certPath: string,
    readonly label: string
  ) {
    this.appDataDir = mkdtempSync(join(tmpdir(), `mw-bw-${label}-`));
  }

  run(args: string[], extraEnv: Record<string, string> = {}): Promise<BwResult> {
    const env: Record<string, string> = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (value === undefined || key.startsWith('BW_') || key === 'NODE_OPTIONS') continue;
      env[key] = value;
    }
    Object.assign(env, {
      BITWARDENCLI_APPDATA_DIR: this.appDataDir,
      NODE_EXTRA_CA_CERTS: this.certPath,
      BW_NOINTERACTION: 'true',
      NO_COLOR: '1',
      ...(this.session ? { BW_SESSION: this.session } : {}),
      ...extraEnv,
    });
    return new Promise((resolve, reject) => {
      const child = spawn(this.bin, [...args, '--nointeraction'], { env, stdio: ['pipe', 'pipe', 'pipe'] });
      child.stdin.end();
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (chunk) => (stdout += chunk));
      child.stderr.on('data', (chunk) => (stderr += chunk));
      child.on('error', reject);
      child.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
    });
  }

  // Runs a command that must succeed; returns stdout.
  async ok(args: string[], extraEnv: Record<string, string> = {}): Promise<string> {
    const result = await this.run(args, extraEnv);
    if (result.code !== 0) {
      throw new Error(`bw ${args.join(' ')} [${this.label}] exited ${result.code}\nstdout: ${result.stdout}\nstderr: ${result.stderr}`);
    }
    return result.stdout;
  }

  // Runs with --response and returns `data` of the JSON envelope.
  async data<T = any>(args: string[], extraEnv: Record<string, string> = {}): Promise<T> {
    const stdout = await this.ok([...args, '--response'], extraEnv);
    let envelope: { success: boolean; data?: T; message?: string };
    try {
      envelope = JSON.parse(stdout);
    } catch {
      throw new Error(`bw ${args.join(' ')} [${this.label}] printed non-JSON: ${stdout}`);
    }
    if (!envelope.success) throw new Error(`bw ${args.join(' ')} [${this.label}] failed: ${envelope.message}`);
    return envelope.data as T;
  }

  dispose(): void {
    rmSync(this.appDataDir, { recursive: true, force: true });
  }
}
