import { LIMITS } from '../../config/limits';
import type { IconSource } from '../../main/config';
import { sha256Hex } from '../../platform/crypto';
import { isSafeWebsiteIconContentType } from '../../utils/content-type';

// Website icons for vault items, fetched from a public icon service so
// clients never contact the sites themselves. ICON_SOURCE picks the service:
// `favicon` (favicon.im, then Bitwarden's), `bitwarden`, or `off`.

interface Upstream {
  url(host: string): string;
  // An image the service returns when it has no icon for the site.
  placeholder?: { byteLength: number; sha256: string };
}

const FAVICON_IM: Upstream = {
  url: (host) => `https://favicon.im/zh/${host}?larger=true&throw-error-on-404=true`,
};

const BITWARDEN: Upstream = {
  url: (host) => `https://icons.bitwarden.net/${host}/icon.png`,
  placeholder: { byteLength: 500, sha256: 'aaa64871332ad5b7d28fe8874efb19c2d9cc2f1e6de75d52b080b438225a0783' },
};

const UPSTREAMS: Record<IconSource, Upstream[]> = {
  favicon: [FAVICON_IM, BITWARDEN],
  bitwarden: [BITWARDEN],
  off: [],
};

const TIMEOUT_MS = 2500;
const MAX_BYTES = 256 * 1024;

export interface Icon {
  body: Uint8Array<ArrayBuffer>;
  contentType: string;
}

// A host name as clients send it; null for anything that is not one.
export function normalizeHost(raw: string): string | null {
  const host = raw.trim().toLowerCase().replace(/\.+$/, '');
  if (!host || host.includes('/') || host.includes('\\')) return null;
  try {
    return new URL(`https://${host}`).hostname === host ? host : null;
  } catch {
    return null;
  }
}

async function readLimited(response: Response, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer> | null> {
  const declared = Number(response.headers.get('Content-Length'));
  if (declared > MAX_BYTES || !response.body) return null;
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BYTES) return null;
      chunks.push(value);
    }
  } finally {
    void reader.cancel().catch(() => undefined);
  }
  if (signal.aborted || total === 0) return null;
  return Buffer.concat(chunks);
}

async function fetchFrom(upstream: Upstream, host: string): Promise<Icon | null> {
  const signal = AbortSignal.timeout(TIMEOUT_MS);
  try {
    const response = await fetch(upstream.url(encodeURIComponent(host)), {
      headers: { 'User-Agent': 'MoliWarden/1.0' },
      redirect: 'follow',
      signal,
    });
    const contentType = response.headers.get('Content-Type') ?? '';
    if (!response.ok || !isSafeWebsiteIconContentType(contentType)) return null;
    const body = await readLimited(response, signal);
    if (!body) return null;
    const { placeholder } = upstream;
    if (placeholder && body.byteLength === placeholder.byteLength && sha256Hex(body) === placeholder.sha256) return null;
    return { body, contentType };
  } catch {
    return null;
  }
}

export async function findIcon(source: IconSource, host: string): Promise<Icon | null> {
  for (const upstream of UPSTREAMS[source]) {
    const icon = await fetchFrom(upstream, host);
    if (icon) return icon;
  }
  return null;
}

// Shown when no icon is found, unless the client asked for a 404.
export const GLOBE_ICON = `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="Globe icon"><circle cx="48" cy="48" r="34" fill="none" stroke="#a3a3a3" stroke-width="6"/><path d="M14 48h68M48 14c10 10 16 21.5 16 34s-6 24-16 34c-10-10-16-21.5-16-34s6-24 16-34zm-24 10c8 5 17 8 24 8s16-3 24-8m-48 48c8-5 17-8 24-8s16 3 24 8" fill="none" stroke="#a3a3a3" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export const ICON_CACHE_CONTROL = `public, max-age=${LIMITS.cache.iconTtlSeconds}, immutable`;
