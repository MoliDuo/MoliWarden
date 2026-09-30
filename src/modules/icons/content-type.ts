// Icons are served from this origin, so only plain images are passed on.
const SAFE_ICON_MEDIA_TYPES = new Set([
  'image/avif',
  'image/bmp',
  'image/gif',
  'image/jpeg',
  'image/png',
  'image/vnd.microsoft.icon',
  'image/webp',
  'image/x-icon',
]);

function normalizeMediaType(contentType: string | null | undefined): string {
  return String(contentType || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
}

export function isSafeWebsiteIconContentType(contentType: string | null | undefined): boolean {
  return SAFE_ICON_MEDIA_TYPES.has(normalizeMediaType(contentType));
}
