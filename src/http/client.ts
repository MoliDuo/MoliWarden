// Who is on the other end of a request, as far as the platform can tell.
//
// Vercel's edge overwrites X-Forwarded-For / X-Real-IP with the real client
// address, so they can be trusted there. CF-Connecting-IP is not set by
// Vercel and would be fully client-controlled, so it is ignored.

export function clientIp(request: Request): string | null {
  const candidates = [
    request.headers.get('X-Vercel-Forwarded-For')?.split(',')[0]?.trim(),
    request.headers.get('X-Real-IP')?.trim(),
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim(),
  ];
  return candidates.find((candidate) => !!candidate) ?? null;
}

export function clientCountry(request: Request): string | null {
  return request.headers.get('X-Vercel-IP-Country') || null;
}

function parseIpv4Octets(input: string): number[] | null {
  const parts = input.split('.');
  if (parts.length !== 4) return null;

  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    octets.push(value);
  }
  return octets;
}

function parseIpv6Hextets(input: string): number[] | null {
  let value = input.trim().toLowerCase();
  if (!value) return null;

  if (value.startsWith('[') && value.endsWith(']')) {
    value = value.slice(1, -1);
  }
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) {
    value = value.slice(0, zoneIndex);
  }
  if (!value.includes(':')) return null;

  // Handle IPv4-mapped tail (e.g. ::ffff:192.0.2.1).
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4Tail = value.slice(lastColon + 1);
    const octets = parseIpv4Octets(ipv4Tail);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }

  const doubleColon = value.indexOf('::');
  if (doubleColon !== value.lastIndexOf('::')) return null;

  const parsePart = (part: string): number | null => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    const n = parseInt(part, 16);
    return Number.isNaN(n) ? null : n;
  };

  const parseParts = (parts: string[]): number[] | null => {
    const out: number[] = [];
    for (const p of parts) {
      if (!p) return null;
      const n = parsePart(p);
      if (n === null) return null;
      out.push(n);
    }
    return out;
  };

  if (doubleColon >= 0) {
    const [headRaw, tailRaw] = value.split('::');
    const head = headRaw ? headRaw.split(':') : [];
    const tail = tailRaw ? tailRaw.split(':') : [];

    const headNums = parseParts(head);
    const tailNums = parseParts(tail);
    if (!headNums || !tailNums) return null;

    const missing = 8 - (headNums.length + tailNums.length);
    if (missing < 1) return null;

    return [...headNums, ...new Array<number>(missing).fill(0), ...tailNums];
  }

  const all = parseParts(value.split(':'));
  if (!all || all.length !== 8) return null;
  return all;
}

function normalizeClientIpForRateLimit(rawIp: string): string | null {
  const input = rawIp.trim();
  if (!input) return null;

  const ipv4 = parseIpv4Octets(input);
  if (ipv4) {
    return `ip4:${ipv4.join('.')}`;
  }

  const ipv6 = parseIpv6Hextets(input);
  if (!ipv6) return null;

  // Handle IPv4-mapped / IPv4-compatible IPv6 as IPv4 identity.
  // Examples: ::ffff:192.0.2.1, ::192.0.2.1
  if (
    ipv6[0] === 0 &&
    ipv6[1] === 0 &&
    ipv6[2] === 0 &&
    ipv6[3] === 0 &&
    ipv6[4] === 0 &&
    (ipv6[5] === 0xffff || ipv6[5] === 0)
  ) {
    const octets = [ipv6[6] >> 8, ipv6[6] & 0xff, ipv6[7] >> 8, ipv6[7] & 0xff];
    return `ip4:${octets.join('.')}`;
  }

  // Collapse to /64 to reduce brute-force bypass via IPv6 address rotation.
  const prefix64 = ipv6
    .slice(0, 4)
    .map(part => part.toString(16).padStart(4, '0'))
    .join(':');
  return `ip6:${prefix64}`;
}

function isLocalRequest(request: Request): boolean {
  const isLoopbackHost = (host: string | null): boolean => {
    if (!host) return false;
    const normalized = host.split(':')[0].trim().toLowerCase();
    return (
      normalized === 'localhost' ||
      normalized.endsWith('.localhost') ||
      normalized === '127.0.0.1' ||
      normalized === '0.0.0.0' ||
      normalized === '::1' ||
      normalized === '[::1]'
    );
  };

  try {
    if (isLoopbackHost(new URL(request.url).hostname)) return true;
  } catch {
    // Ignore malformed URL and fall back to Host header check.
  }

  return isLoopbackHost(request.headers.get('Host'));
}

// The address rate limits count against: an IPv4 address or an IPv6 /64.
// Null when the request carries no usable address.
export function clientAddress(request: Request): string | null {
  const raw = clientIp(request);
  if (raw) {
    const normalized = normalizeClientIpForRateLimit(raw);
    if (normalized) return normalized;
  }

  // Local dev (localhost): allow a deterministic loopback identifier.
  if (isLocalRequest(request)) {
    return 'ip4:127.0.0.1';
  }

  return null;
}
