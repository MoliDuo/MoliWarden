// A minimal in-memory WebDAV server for the backup tests: Basic auth, MKCOL,
// PUT, GET, HEAD, DELETE and PROPFIND with Depth 1.
import { createServer, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface FakeWebDav {
  url: string;
  files: Map<string, { bytes: Buffer; modifiedAt: Date }>;
  close(): Promise<void>;
}

const clean = (pathname: string) => decodeURIComponent(pathname).split('/').filter(Boolean).join('/');
const parentOf = (path: string) => path.split('/').slice(0, -1).join('/');

async function body(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

export async function startFakeWebDav(username: string, password: string): Promise<FakeWebDav> {
  const files = new Map<string, { bytes: Buffer; modifiedAt: Date }>();
  const folders = new Set<string>(['']);
  const expected = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;

  const server = createServer(async (req, res) => {
    if (req.headers.authorization !== expected) return void res.writeHead(401).end();
    const path = clean(new URL(req.url!, 'http://x').pathname);
    const data = await body(req);
    switch (req.method) {
      case 'MKCOL':
        if (folders.has(path)) return void res.writeHead(405).end();
        if (!folders.has(parentOf(path))) return void res.writeHead(409).end();
        folders.add(path);
        return void res.writeHead(201).end();
      case 'PUT':
        if (!folders.has(parentOf(path))) return void res.writeHead(409).end();
        files.set(path, { bytes: data, modifiedAt: new Date() });
        return void res.writeHead(201).end();
      case 'GET':
      case 'HEAD': {
        const file = files.get(path);
        if (!file) return void res.writeHead(404).end();
        res.writeHead(200, { 'Content-Length': String(file.bytes.length) });
        return void res.end(req.method === 'GET' ? file.bytes : undefined);
      }
      case 'DELETE':
        if (!files.delete(path)) return void res.writeHead(404).end();
        return void res.writeHead(204).end();
      case 'PROPFIND': {
        if (!folders.has(path)) return void res.writeHead(404).end();
        const entry = (href: string, inner: string) => `<d:response><d:href>/${href}</d:href><d:propstat><d:prop>${inner}</d:prop></d:propstat></d:response>`;
        const folder = (p: string) => entry(`${p}/`.replace(/^\//, ''), '<d:resourcetype><d:collection/></d:resourcetype>');
        const children = [
          folder(path),
          ...[...folders].filter((p) => p && parentOf(p) === path).map(folder),
          ...[...files]
            .filter(([p]) => parentOf(p) === path)
            .map(([p, file]) =>
              entry(p, `<d:resourcetype/><d:getcontentlength>${file.bytes.length}</d:getcontentlength><d:getlastmodified>${file.modifiedAt.toUTCString()}</d:getlastmodified>`),
            ),
        ];
        res.writeHead(207, { 'Content-Type': 'application/xml; charset=utf-8' });
        return void res.end(`<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">${children.join('')}</d:multistatus>`);
      }
      default:
        res.writeHead(405).end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    files,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
