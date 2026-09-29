import type { Context } from 'hono';
import type { BlobStore } from '../platform/blob';
import type { TokenService, TokenType } from '../platform/tokens';
import type { Actor } from './authenticate';
import { badRequest, notFound, payloadTooLarge } from './errors';

// Files clients upload (attachments, Send files) and download again. They
// are encrypted by the client; the server only stores the bytes.

export const FILE_TOKEN_TTL_SECONDS = 300;
// Larger files are fetched from storage directly, through a presigned URL,
// rather than through the function.
const INLINE_DOWNLOAD_MAX_BYTES = 4 * 1024 * 1024;
const MULTIPART_OVERHEAD_BYTES = 256 * 1024;
const ACTIVE_MEDIA_TYPES = new Set(['application/xhtml+xml', 'application/xml', 'image/svg+xml', 'text/html', 'text/xml']);

export interface Upload {
  bytes: Uint8Array<ArrayBuffer>;
  contentType: string;
}

export function sizeName(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

export const maxSizeName = (bytes: number) => `${(bytes / 1024 ** 2).toFixed(1).replace(/\.0$/, '')} MB`;

// Upload URLs look like Azure blob SAS URLs, which is what official clients
// expect for fileUploadType 1. The token stands in for the bearer token,
// which official clients do not send there, and is good for one file only.
export function uploadUrl(c: Context, tokens: TokenService, typ: TokenType, actor: Actor, path: string, file: string): string {
  const token = tokens.sign(
    typ,
    {
      sub: actor.user.id,
      sstamp: actor.user.securityStamp,
      did: actor.device?.deviceIdentifier,
      dstamp: actor.device?.sessionStamp,
      file,
    },
    FILE_TOKEN_TTL_SECONDS,
  );
  return `${new URL(c.req.url).origin}${path}?sv=2023-11-03&se=2099-12-31T23:59:59Z&token=${encodeURIComponent(token)}`;
}

async function readAtMost(body: ReadableStream<Uint8Array>, maxBytes: number, tooLarge: string): Promise<Uint8Array<ArrayBuffer>> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw payloadTooLarge(tooLarge);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

// The uploaded file: the raw body, or the "data" part of a multipart form.
// `expectedSize` is the size the client announced when it asked to upload.
export async function readUpload(
  c: Context,
  options: { maxBytes: number; tooLarge: string; expectedSize: number | null; sizeMismatch: string },
): Promise<Upload> {
  const contentType = c.req.header('Content-Type') ?? '';
  const declared = Number(c.req.header('Content-Length'));
  const multipart = contentType.includes('multipart/form-data');
  if (declared > options.maxBytes + (multipart ? MULTIPART_OVERHEAD_BYTES : 0)) throw payloadTooLarge(options.tooLarge);

  let upload: Upload;
  if (multipart) {
    const file = (await c.req.formData()).get('data');
    if (!(file instanceof File)) throw badRequest('No file uploaded');
    if (file.size > options.maxBytes) throw payloadTooLarge(options.tooLarge);
    upload = { bytes: new Uint8Array(await file.arrayBuffer()), contentType: file.type };
  } else {
    if (!c.req.raw.body) throw badRequest('No file uploaded');
    upload = { bytes: await readAtMost(c.req.raw.body, options.maxBytes, options.tooLarge), contentType };
  }
  if (!upload.bytes.byteLength) throw badRequest('No file uploaded');
  if (options.expectedSize !== null && upload.bytes.byteLength !== options.expectedSize) throw badRequest(options.sizeMismatch);
  return { ...upload, contentType: upload.contentType || 'application/octet-stream' };
}

// Stored files are never shown inline: a browser would run an HTML or SVG
// file on the server's origin.
function downloadContentType(contentType: string): string {
  const mediaType = contentType.split(';', 1)[0].trim().toLowerCase();
  return !mediaType || ACTIVE_MEDIA_TYPES.has(mediaType) ? 'application/octet-stream' : contentType;
}

export async function fileDownload(blobs: BlobStore, key: string, fileName: string, missing: string): Promise<Response> {
  const meta = await blobs.head(key);
  if (!meta) throw notFound(missing);
  const contentType = downloadContentType(meta.contentType);
  const contentDisposition = `attachment; filename="${fileName.replace(/[\r\n"]/g, '_')}"`;
  if (meta.size > INLINE_DOWNLOAD_MAX_BYTES) {
    const location = await blobs.presign(key, { contentDisposition, contentType });
    return new Response(null, { status: 302, headers: { Location: location, 'Cache-Control': 'no-store' } });
  }
  const object = await blobs.get(key);
  if (!object) throw notFound(missing);
  return new Response(object.body, {
    headers: {
      'Content-Type': contentType,
      'Content-Length': String(object.size),
      'Content-Disposition': contentDisposition,
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
