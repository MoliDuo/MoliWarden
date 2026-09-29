function normalizeDeviceIdentifier(value: string | undefined | null): string | null {
  if (!value) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;
  return normalized.slice(0, 128);
}

export function readActingDeviceIdentifier(request: Request): string | null {
  return normalizeDeviceIdentifier(request.headers.get('X-MoliWarden-Acting-Device-Id'));
}
