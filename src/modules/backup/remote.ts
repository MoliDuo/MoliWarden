import { AwsClient } from 'aws4fetch';
import type { S3BackupDestination, WebDavBackupDestination } from '../../../shared/backup-schema';
import { badRequest } from '../../http/errors';
import { checkEndpointUrl, RemoteError, type RemoteFetch } from './endpoint';
import type { Destination } from './settings';

// The storage a destination points at, as files under its root folder.
// Paths are relative to that root and use "/".

export interface RemoteItem {
  path: string;
  name: string;
  isDirectory: boolean;
  size: number | null;
  modifiedAt: string | null;
}

export interface RemoteStore {
  provider: Destination['type'];
  // The full path of a file, as shown to admins.
  location(path: string): string;
  list(dir: string): Promise<RemoteItem[]>;
  // Null when there is no such file.
  get(path: string): Promise<Uint8Array<ArrayBuffer> | null>;
  size(path: string): Promise<number | null>;
  put(path: string, bytes: Uint8Array<ArrayBuffer>, contentType: string): Promise<void>;
  delete(path: string): Promise<void>;
}

// "a//b/" -> "a/b"; "." and ".." are refused.
export function normalizePath(path: string): string {
  const parts = path.replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.some((part) => part === '.' || part === '..')) throw badRequest('Invalid remote backup path');
  return parts.join('/');
}

export const parentOf = (path: string): string | null => (path ? path.split('/').slice(0, -1).join('/') : null);
const join = (...parts: string[]) => parts.map(normalizePath).filter(Boolean).join('/');
const encodePath = (path: string) => path.split('/').filter(Boolean).map(encodeURIComponent).join('/');
const httpDate = (value: string | null) => (value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null);

function xmlBlocks(xml: string, tag: string): string[] {
  const pattern = new RegExp(`<(?:[\\w-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${tag}>`, 'gi');
  return [...xml.matchAll(pattern)].map((match) => match[1]);
}

function xmlText(xml: string, tag: string): string | null {
  const value = xmlBlocks(xml, tag)[0];
  if (value === undefined) return null;
  return value
    .trim()
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

async function failure(provider: string, action: string, response: Response): Promise<RemoteError> {
  const body = await response.text().catch(() => '');
  const code = /<(?:\w+:)?Code>([^<]+)</.exec(body)?.[1];
  return new RemoteError(`${provider} ${action} failed (HTTP ${response.status}${code ? ` ${code}` : ''})`);
}

function s3Store(config: S3BackupDestination, remoteFetch: RemoteFetch, allowPrivate: boolean): RemoteStore {
  const endpoint = new URL(checkEndpointUrl(config.endpoint, 'S3 endpoint', allowPrivate));
  const client = new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    region: config.region || 'auto',
    service: 's3',
  });
  const bucketUrl = (() => {
    if (config.addressingStyle === 'path-style') return `${endpoint.toString().replace(/\/+$/, '')}/${encodeURIComponent(config.bucket)}`;
    const url = new URL(endpoint);
    if (url.hostname !== config.bucket && !url.hostname.startsWith(`${config.bucket}.`)) url.hostname = `${config.bucket}.${url.hostname}`;
    return url.toString().replace(/\/+$/, '');
  })();
  const keyOf = (path: string) => join(config.rootPath, path);

  async function send(method: string, url: string, body?: Uint8Array<ArrayBuffer>, contentType?: string): Promise<Response> {
    const signed = await client.sign(url, { method, body, headers: contentType ? { 'Content-Type': contentType } : {} });
    return remoteFetch(signed.url, { method, headers: signed.headers, body });
  }
  const objectUrl = (path: string) => `${bucketUrl}/${encodePath(keyOf(path))}`;

  return {
    provider: 's3',
    location: keyOf,
    async list(dir) {
      const root = normalizePath(config.rootPath);
      const prefix = keyOf(dir) ? `${keyOf(dir)}/` : '';
      const relative = (key: string) => (root ? key.slice(root.length + 1) : key);
      const items: RemoteItem[] = [];
      let token = '';
      do {
        const url = new URL(bucketUrl);
        url.searchParams.set('list-type', '2');
        url.searchParams.set('delimiter', '/');
        if (prefix) url.searchParams.set('prefix', prefix);
        if (token) url.searchParams.set('continuation-token', token);
        const response = await send('GET', url.toString());
        if (!response.ok) throw await failure('S3', 'listing', response);
        const xml = await response.text();
        for (const block of xmlBlocks(xml, 'CommonPrefixes')) {
          const path = relative((xmlText(block, 'Prefix') ?? '').replace(/\/+$/, ''));
          if (path) items.push({ path, name: path.split('/').pop()!, isDirectory: true, size: null, modifiedAt: null });
        }
        for (const block of xmlBlocks(xml, 'Contents')) {
          const key = xmlText(block, 'Key') ?? '';
          const path = relative(key);
          if (!path || key.endsWith('/')) continue;
          items.push({
            path,
            name: path.split('/').pop()!,
            isDirectory: false,
            size: Number(xmlText(block, 'Size')) || 0,
            modifiedAt: httpDate(xmlText(block, 'LastModified')),
          });
        }
        token = xmlText(xml, 'IsTruncated') === 'true' ? (xmlText(xml, 'NextContinuationToken') ?? '') : '';
      } while (token);
      return items;
    },
    async get(path) {
      const response = await send('GET', objectUrl(path));
      if (response.status === 404) return null;
      if (!response.ok) throw await failure('S3', 'download', response);
      return new Uint8Array(await response.arrayBuffer());
    },
    async size(path) {
      const response = await send('HEAD', objectUrl(path));
      if (response.status === 404) return null;
      if (!response.ok) throw await failure('S3', 'lookup', response);
      return Number(response.headers.get('Content-Length'));
    },
    async put(path, bytes, contentType) {
      const response = await send('PUT', objectUrl(path), bytes, contentType);
      if (!response.ok) throw await failure('S3', 'upload', response);
      await response.body?.cancel();
    },
    async delete(path) {
      const response = await send('DELETE', objectUrl(path));
      if (!response.ok && response.status !== 404) throw await failure('S3', 'delete', response);
      await response.body?.cancel();
    },
  };
}

const PROPFIND_BODY =
  '<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/><getcontentlength/><getlastmodified/></prop></propfind>';

function webDavStore(config: WebDavBackupDestination, remoteFetch: RemoteFetch, allowPrivate: boolean): RemoteStore {
  const base = new URL(`${checkEndpointUrl(config.baseUrl, 'WebDAV server URL', allowPrivate)}/`);
  const authorization = `Basic ${Buffer.from(`${config.username}:${config.password}`).toString('base64')}`;
  const fullPath = (path: string) => join(config.remotePath, path);
  const urlOf = (full: string) => new URL(encodePath(full), base).toString();
  const request = (method: string, full: string, init: RequestInit = {}) =>
    remoteFetch(urlOf(full), { ...init, method, headers: { Authorization: authorization, ...init.headers } });
  // Folders this store has made sure exist.
  const folders = new Set<string>();

  async function ensureFolder(full: string): Promise<void> {
    let current = '';
    for (const part of full.split('/').filter(Boolean)) {
      current = current ? `${current}/${part}` : part;
      if (folders.has(current)) continue;
      const response = await request('MKCOL', `${current}/`);
      await response.body?.cancel();
      // 405: it already exists.
      if (![200, 201, 204, 405].includes(response.status)) throw await failure('WebDAV', 'folder creation', response);
      folders.add(current);
    }
  }

  return {
    provider: 'webdav',
    location: fullPath,
    async list(dir) {
      const root = normalizePath(config.remotePath);
      const target = fullPath(dir);
      const response = await request('PROPFIND', target ? `${target}/` : '', {
        headers: { Depth: '1', 'Content-Type': 'application/xml; charset=utf-8' },
        body: PROPFIND_BODY,
      });
      if (response.status === 404) return [];
      if (!response.ok) throw await failure('WebDAV', 'listing', response);
      const basePath = normalizePath(decodeURIComponent(base.pathname));
      const items: RemoteItem[] = [];
      for (const block of xmlBlocks(await response.text(), 'response')) {
        const href = xmlText(block, 'href');
        if (!href) continue;
        let full = normalizePath(decodeURIComponent(new URL(href, base).pathname));
        if (basePath) {
          if (!full.startsWith(`${basePath}/`)) continue;
          full = full.slice(basePath.length + 1);
        }
        if (full === target || parentOf(full) !== target) continue;
        const path = root ? full.slice(root.length + 1) : full;
        const isDirectory = /<(?:[\w-]+:)?collection\b/i.test(xmlBlocks(block, 'resourcetype')[0] ?? '');
        const size = Number(xmlText(block, 'getcontentlength'));
        items.push({
          path,
          name: path.split('/').pop()!,
          isDirectory,
          size: isDirectory || !Number.isFinite(size) ? null : size,
          modifiedAt: httpDate(xmlText(block, 'getlastmodified')),
        });
      }
      return items;
    },
    async get(path) {
      const response = await request('GET', fullPath(path));
      if (response.status === 404) return null;
      if (!response.ok) throw await failure('WebDAV', 'download', response);
      return new Uint8Array(await response.arrayBuffer());
    },
    async size(path) {
      const response = await request('HEAD', fullPath(path));
      if (response.status === 404) return null;
      if (!response.ok) throw await failure('WebDAV', 'lookup', response);
      return Number(response.headers.get('Content-Length'));
    },
    async put(path, bytes, contentType) {
      const full = fullPath(path);
      const folder = parentOf(full);
      if (folder) await ensureFolder(folder);
      const response = await request('PUT', full, { headers: { 'Content-Type': contentType }, body: bytes });
      if (!response.ok) throw await failure('WebDAV', 'upload', response);
      await response.body?.cancel();
    },
    async delete(path) {
      const response = await request('DELETE', fullPath(path));
      if (!response.ok && response.status !== 404) throw await failure('WebDAV', 'delete', response);
      await response.body?.cancel();
    },
  };
}

export function openRemoteStore(destination: Destination, remoteFetch: RemoteFetch, allowPrivate: boolean): RemoteStore {
  return destination.type === 's3'
    ? s3Store(destination.destination as S3BackupDestination, remoteFetch, allowPrivate)
    : webDavStore(destination.destination as WebDavBackupDestination, remoteFetch, allowPrivate);
}
