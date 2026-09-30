import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { badRequest, HttpError } from '../../http/errors';

// Backup destinations are URLs an admin types in, and the server fetches
// them. So that they cannot be pointed at the server's own network, a
// destination must be a public http(s) host: checked on save by its name,
// and on every request by the addresses it resolves to. Redirects are not
// followed, since their target is not checked.

// A destination that cannot be used or did not answer as expected. The
// message names the host and the HTTP status, never a credential.
export class RemoteError extends HttpError {
  constructor(message: string) {
    super(502, message);
    this.name = 'RemoteError';
  }
}

const BLOCKED = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3],
] as const) {
  BLOCKED.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['::', 127], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32],
] as const) {
  BLOCKED.addSubnet(network, prefix, 'ipv6');
}

const PRIVATE_NAME = /(^|\.)(localhost|localdomain|local|internal|lan|home\.arpa|localtest\.me|lvh\.me|vcap\.me|nip\.io|sslip\.io|xip\.io)$/;

function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 0) return false;
  if (family === 6) {
    // IPv4-mapped addresses are judged by the IPv4 address they carry.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
    if (mapped) return BLOCKED.check(mapped, 'ipv4');
  }
  return BLOCKED.check(address, family === 6 ? 'ipv6' : 'ipv4');
}

// The host of a URL, lower-cased and without brackets or a trailing dot.
const hostOf = (url: URL) => url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

// Checks what can be checked without the network. Returns the URL without
// a trailing slash; the message names the setting by `label`.
export function checkEndpointUrl(value: string, label: string, allowPrivate: boolean): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw badRequest(`${label} must be a valid URL`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw badRequest(`${label} must start with http:// or https://`);
  if (url.username || url.password) throw badRequest(`${label} must not include credentials`);
  if (url.search || url.hash) throw badRequest(`${label} must not include query or fragment`);
  const host = hostOf(url);
  if (!host) throw badRequest(`${label} host is required`);
  if (!allowPrivate && (PRIVATE_NAME.test(host) || isBlockedAddress(host))) throw badRequest(`${label} host is not allowed`);
  return url.toString().replace(/\/+$/, '');
}

async function assertPublicHost(url: URL): Promise<void> {
  const host = hostOf(url);
  const addresses = isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((entry) => entry.address);
  if (!addresses.length) throw new RemoteError(`Could not resolve ${host}`);
  if (addresses.some(isBlockedAddress)) throw new RemoteError(`${host} resolves to an address that is not allowed`);
}

export interface RemoteFetch {
  (url: string | URL, init: RequestInit): Promise<Response>;
}

export function createRemoteFetch(allowPrivate: boolean): RemoteFetch {
  return async (input, init) => {
    const url = new URL(input);
    if (!allowPrivate) await assertPublicHost(url);
    let response: Response;
    try {
      response = await fetch(url, { ...init, redirect: 'manual' });
    } catch (error) {
      throw new RemoteError(`Could not reach ${url.host}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new RemoteError(`${url.host} answered with a redirect (${response.status}), which is not followed`);
    }
    return response;
  };
}
