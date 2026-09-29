import { AwsClient } from 'aws4fetch';

// Attachment and Send files on any S3-compatible service (AWS S3, R2,
// Backblaze B2, MinIO, ...). Keys are "<cipher>/<attachment>" and
// "sends/<send>/<file>".

// As the deployment configures it; unset values mean no blob storage.
export interface S3Config {
  endpoint?: string;
  bucket?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  region?: string;
  forcePathStyle?: string;
}

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
const PRESIGNED_URL_TTL_SECONDS = 120;

export interface BlobMeta {
  size: number;
  contentType: string;
}

export interface BlobStore {
  // False until all four S3 settings are set.
  readonly configured: boolean;
  put(key: string, body: Uint8Array<ArrayBuffer>, contentType?: string): Promise<void>;
  get(key: string): Promise<(BlobMeta & { body: ReadableStream | null }) | null>;
  head(key: string): Promise<BlobMeta | null>;
  delete(key: string): Promise<void>;
  presign(key: string, options?: { contentDisposition?: string; contentType?: string }): Promise<string>;
}

export const attachmentKey = (cipherId: string, attachmentId: string) => `${cipherId}/${attachmentId}`;
export const sendFileKey = (sendId: string, fileId: string) => `sends/${sendId}/${fileId}`;

export const BLOB_STORAGE_MISSING =
  'File storage is not configured. Set S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY.';

const metaOf = (response: Response): BlobMeta => ({
  size: Number(response.headers.get('content-length')) || 0,
  contentType: response.headers.get('content-type') || DEFAULT_CONTENT_TYPE,
});

// A failed S3 request. `message` is safe to show: the HTTP status and the
// S3 error code (SignatureDoesNotMatch, NoSuchBucket, ...) carry no
// secrets. The full answer of the service is in `detail`, for the logs.
export class BlobStoreError extends Error {
  constructor(
    message: string,
    readonly detail = '',
  ) {
    super(message);
    this.name = 'BlobStoreError';
  }
}

async function failure(action: string, response: Response): Promise<BlobStoreError> {
  const detail = action === 'head' ? '' : await response.text().catch(() => '');
  const code = detail.match(/<Code>([A-Za-z0-9.]+)<\/Code>/)?.[1];
  const reason = [`HTTP ${response.status}`, code].filter(Boolean).join(' ');
  return new BlobStoreError(
    `File storage error (${reason}). Check the S3_* settings and the function logs.`,
    `S3 ${action} failed (${response.status}): ${detail.slice(0, 500)}`,
  );
}

export function createBlobStore(s3: S3Config): BlobStore {
  const endpoint = (s3.endpoint ?? '').trim().replace(/\/+$/, '');
  const bucket = (s3.bucket ?? '').trim();
  const accessKeyId = (s3.accessKeyId ?? '').trim();
  const secretAccessKey = (s3.secretAccessKey ?? '').trim();
  const configured = !!(endpoint && bucket && accessKeyId && secretAccessKey);
  const pathStyle = (s3.forcePathStyle ?? '1').trim() !== '0';
  const client = configured
    ? new AwsClient({ accessKeyId, secretAccessKey, region: (s3.region ?? '').trim() || 'auto', service: 's3' })
    : null;

  function url(key: string): string {
    const path = key.split('/').map(encodeURIComponent).join('/');
    if (pathStyle) return `${endpoint}/${encodeURIComponent(bucket)}/${path}`;
    const virtualHost = new URL(endpoint);
    virtualHost.hostname = `${bucket}.${virtualHost.hostname}`;
    virtualHost.pathname = `/${path}`;
    return virtualHost.toString();
  }

  function required(): AwsClient {
    if (!client) throw new BlobStoreError(BLOB_STORAGE_MISSING);
    return client;
  }

  return {
    configured,
    async put(key, body, contentType = DEFAULT_CONTENT_TYPE) {
      const response = await required().fetch(url(key), { method: 'PUT', headers: { 'Content-Type': contentType }, body });
      if (!response.ok) throw await failure('upload', response);
    },
    async get(key) {
      if (!client) return null;
      const response = await client.fetch(url(key), { method: 'GET' });
      if (response.status === 404) return null;
      if (!response.ok) throw await failure('download', response);
      return { ...metaOf(response), body: response.body };
    },
    async head(key) {
      if (!client) return null;
      const response = await client.fetch(url(key), { method: 'HEAD' });
      if (response.status === 404) return null;
      if (!response.ok) throw await failure('head', response);
      return metaOf(response);
    },
    async delete(key) {
      if (!client) return;
      const response = await client.fetch(url(key), { method: 'DELETE' });
      if (!response.ok && response.status !== 404) throw await failure('delete', response);
    },
    async presign(key, options = {}) {
      const signed = new URL(url(key));
      signed.searchParams.set('X-Amz-Expires', String(PRESIGNED_URL_TTL_SECONDS));
      if (options.contentDisposition) signed.searchParams.set('response-content-disposition', options.contentDisposition);
      if (options.contentType) signed.searchParams.set('response-content-type', options.contentType);
      return (await required().sign(signed.toString(), { method: 'GET', aws: { signQuery: true } })).url;
    },
  };
}
