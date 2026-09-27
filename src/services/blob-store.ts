import { AwsClient } from 'aws4fetch';
import { Env } from '../types';

// Attachment / Send file storage on any S3-compatible service
// (AWS S3, Cloudflare R2's S3 API, Backblaze B2, MinIO, SeaweedFS, ...).

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
// Kept for backup-import compatibility: MoliWarden never uses KV storage.
export const KV_MAX_OBJECT_BYTES = 25 * 1024 * 1024;
// Vercel Functions reject request bodies above 4.5 MB. Leave headroom for the
// multipart envelope official clients wrap uploads in.
const VERCEL_FUNCTION_UPLOAD_MAX_BYTES = 4_400_000;
// Bodies at or below this size are streamed through the function; larger
// downloads are redirected to a short-lived presigned URL.
const INLINE_DOWNLOAD_MAX_BYTES = 4 * 1024 * 1024;
const PRESIGNED_URL_TTL_SECONDS = 120;

export interface BlobObject {
  body: ReadableStream | null;
  size: number;
  contentType: string;
}

export interface PutBlobOptions {
  size: number;
  contentType?: string;
  customMetadata?: Record<string, string>;
}

interface S3Config {
  client: AwsClient;
  endpoint: string;
  bucket: string;
  pathStyle: boolean;
}

let cachedConfig: { key: string; config: S3Config } | null = null;

function readS3Config(env: Env): S3Config | null {
  const endpoint = String(env.S3_ENDPOINT || '').trim().replace(/\/+$/, '');
  const bucket = String(env.S3_BUCKET || '').trim();
  const accessKeyId = String(env.S3_ACCESS_KEY_ID || '').trim();
  const secretAccessKey = String(env.S3_SECRET_ACCESS_KEY || '').trim();
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;

  const region = String(env.S3_REGION || '').trim() || 'auto';
  const pathStyle = String(env.S3_FORCE_PATH_STYLE ?? '1').trim() !== '0';
  const cacheKey = [endpoint, bucket, accessKeyId, secretAccessKey, region, pathStyle].join('\n');
  if (cachedConfig?.key === cacheKey) return cachedConfig.config;

  const config: S3Config = {
    client: new AwsClient({ accessKeyId, secretAccessKey, region, service: 's3' }),
    endpoint,
    bucket,
    pathStyle,
  };
  cachedConfig = { key: cacheKey, config };
  return config;
}

function requireS3Config(env: Env): S3Config {
  const config = readS3Config(env);
  if (!config) throw new Error('Attachment storage is not configured');
  return config;
}

function encodeKey(key: string): string {
  return key.split('/').map((part) => encodeURIComponent(part)).join('/');
}

function objectUrl(config: S3Config, key: string): string {
  if (config.pathStyle) {
    return `${config.endpoint}/${encodeURIComponent(config.bucket)}/${encodeKey(key)}`;
  }
  const url = new URL(config.endpoint);
  url.hostname = `${config.bucket}.${url.hostname}`;
  url.pathname = `/${encodeKey(key)}`;
  return url.toString();
}

async function toBytes(value: string | ArrayBuffer | ArrayBufferView | ReadableStream): Promise<Uint8Array<ArrayBuffer>> {
  if (typeof value === 'string') return new TextEncoder().encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength);
  return new Uint8Array(await new Response(value).arrayBuffer());
}

export const BLOB_STORAGE_MISSING_MESSAGE =
  'File storage is not configured. Set S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY.';

export function getBlobStorageKind(env: Env): 's3' | null {
  return readS3Config(env) ? 's3' : null;
}

export function getBlobStorageMaxBytes(env: Env, configuredLimit: number): number {
  const override = Number(env.MAX_UPLOAD_BYTES || 0);
  const platformLimit = Number.isFinite(override) && override > 0 ? override : VERCEL_FUNCTION_UPLOAD_MAX_BYTES;
  return Math.min(configuredLimit, platformLimit);
}

export function getAttachmentObjectKey(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

export function getSendFileObjectKey(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

export async function putBlobObject(
  env: Env,
  key: string,
  value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
  options: PutBlobOptions
): Promise<void> {
  const config = requireS3Config(env);
  const contentType = options.contentType || DEFAULT_CONTENT_TYPE;
  const body = await toBytes(value);
  const headers: Record<string, string> = { 'Content-Type': contentType };
  for (const [name, metaValue] of Object.entries(options.customMetadata || {})) {
    headers[`x-amz-meta-${name.toLowerCase()}`] = encodeURIComponent(metaValue);
  }
  const response = await config.client.fetch(objectUrl(config, key), {
    method: 'PUT',
    headers,
    body,
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    throw new Error(`S3 upload failed (${response.status}): ${detail.slice(0, 200)}`);
  }
}

export async function getBlobObject(env: Env, key: string): Promise<BlobObject | null> {
  const config = readS3Config(env);
  if (!config) return null;
  const response = await config.client.fetch(objectUrl(config, key), { method: 'GET' });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`S3 download failed (${response.status})`);
  }
  return {
    body: response.body,
    size: Number(response.headers.get('content-length') || 0) || 0,
    contentType: response.headers.get('content-type') || DEFAULT_CONTENT_TYPE,
  };
}

export async function headBlobObject(env: Env, key: string): Promise<{ size: number; contentType: string } | null> {
  const config = readS3Config(env);
  if (!config) return null;
  const response = await config.client.fetch(objectUrl(config, key), { method: 'HEAD' });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`S3 head failed (${response.status})`);
  }
  return {
    size: Number(response.headers.get('content-length') || 0) || 0,
    contentType: response.headers.get('content-type') || DEFAULT_CONTENT_TYPE,
  };
}

export async function deleteBlobObject(env: Env, key: string): Promise<void> {
  const config = readS3Config(env);
  if (!config) return;
  const response = await config.client.fetch(objectUrl(config, key), { method: 'DELETE' });
  if (!response.ok && response.status !== 404) {
    throw new Error(`S3 delete failed (${response.status})`);
  }
}

export async function presignBlobDownloadUrl(
  env: Env,
  key: string,
  options: { contentDisposition?: string; contentType?: string } = {}
): Promise<string> {
  const config = requireS3Config(env);
  const url = new URL(objectUrl(config, key));
  url.searchParams.set('X-Amz-Expires', String(PRESIGNED_URL_TTL_SECONDS));
  if (options.contentDisposition) url.searchParams.set('response-content-disposition', options.contentDisposition);
  if (options.contentType) url.searchParams.set('response-content-type', options.contentType);
  const signed = await config.client.sign(url.toString(), { method: 'GET', aws: { signQuery: true } });
  return signed.url;
}

// Serve a stored blob as a download response: small files are streamed through
// the function; large ones redirect to a presigned URL because Vercel caps
// function response bodies.
export async function blobDownloadResponse(
  env: Env,
  key: string,
  headers: { contentDisposition: string; sanitizeContentType: (value: string) => string }
): Promise<Response | null> {
  const meta = await headBlobObject(env, key);
  if (!meta) return null;
  const contentType = headers.sanitizeContentType(meta.contentType);

  if (meta.size > INLINE_DOWNLOAD_MAX_BYTES) {
    const location = await presignBlobDownloadUrl(env, key, {
      contentDisposition: headers.contentDisposition,
      contentType,
    });
    return new Response(null, {
      status: 302,
      headers: { Location: location, 'Cache-Control': 'no-store' },
    });
  }

  const object = await getBlobObject(env, key);
  if (!object) return null;
  return new Response(object.body, {
    headers: {
      'Content-Type': contentType,
      'Content-Length': String(object.size),
      'Content-Disposition': headers.contentDisposition,
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
