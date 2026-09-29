import { runInBackground } from '../../platform/background';
import { randomAlphanumeric } from '../../platform/crypto';
import type { Db } from '../../platform/db';
import { findInstallation, findPushDevices, saveInstallation, type Installation } from './repo';

// Vercel Functions cannot hold the WebSocket connections desktop and browser
// clients listen on, so those pick up changes on their regular sync. Mobile
// apps are woken up through Bitwarden's push relay instead, which needs an
// installation id; the server registers one the first time it pushes.
//
// Every call returns at once; the relay is contacted in the background, and
// a failure only costs the apps a prompt sync.

const RELAY = 'https://push.bitwarden.com';
const IDENTITY = 'https://identity.bitwarden.com';
const INSTALLATIONS = 'https://api.bitwarden.com/installations';
const TIMEOUT_MS = 5000;

export const PushType = {
  SyncCipherUpdate: 0,
  SyncCipherCreate: 1,
  SyncFolderDelete: 3,
  SyncCiphers: 4,
  SyncVault: 5,
  SyncFolderCreate: 7,
  SyncFolderUpdate: 8,
  SyncCipherDelete: 9,
  LogOut: 11,
  SyncSendCreate: 12,
  SyncSendUpdate: 13,
  SyncSendDelete: 14,
  AuthRequest: 15,
} as const;
export type PushType = (typeof PushType)[keyof typeof PushType];

export interface PushEvent {
  type: PushType;
  userId: string;
  // The device that made the change, which needs no telling.
  deviceIdentifier?: string | null;
  // The item that changed; without one, the whole vault is to be synced.
  item?: { id: string; organizationId?: string | null; collectionIds?: string[] | null; revisionDate?: string };
}

export interface PushDevice {
  userId: string;
  identifier: string;
  type: number;
  pushUuid: string;
  pushToken: string;
}

export interface PushService {
  register(device: PushDevice): void;
  unregister(pushUuid: string | null): void;
  notify(event: PushEvent): void;
  // Tells the user's apps to sign out, then forgets them.
  signOut(userId: string, pushUuids: string[]): void;
}

const DISABLED: PushService = {
  register() {},
  unregister() {},
  notify() {},
  signOut() {},
};

async function call(url: string, init: RequestInit): Promise<Response | null> {
  try {
    const response = await fetch(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (response.ok) return response;
    console.error('Push relay request failed:', url, response.status, await response.text().catch(() => ''));
  } catch (error) {
    console.error('Push relay request failed:', url, error);
  }
  return null;
}

function payloadOf(event: PushEvent, date: string): Record<string, unknown> {
  if (!event.item) return { userId: event.userId, date };
  return {
    id: event.item.id,
    userId: event.userId,
    organizationId: event.item.organizationId ?? null,
    collectionIds: event.item.collectionIds ?? null,
    revisionDate: event.item.revisionDate ?? date,
  };
}

// `installationDomain` names the operator in the address the installation
// is registered under.
export function createPushService(db: Db, options: { disabled: boolean; installationDomain?: string }): PushService {
  if (options.disabled) return DISABLED;
  let token: { value: string; expiresAt: number } | null = null;
  let installing: Promise<Installation | null> | null = null;

  async function findOrRegister(): Promise<Installation | null> {
    const existing = await findInstallation(db);
    if (existing) return existing;
    const email = `${randomAlphanumeric(16).toLowerCase()}@${options.installationDomain || 'example.com'}`;
    const response = await call(INSTALLATIONS, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const body = (await response?.json().catch(() => null)) as { id?: string; key?: string } | null;
    if (!body?.id || !body.key) return null;
    const created = { id: String(body.id), key: String(body.key) };
    await saveInstallation(db, created);
    return created;
  }

  // Looked up once per instance; a failed registration is retried later.
  function installation(): Promise<Installation | null> {
    const pending = (installing ??= findOrRegister());
    pending.then(
      (found) => {
        if (!found && installing === pending) installing = null;
      },
      () => {
        if (installing === pending) installing = null;
      },
    );
    return pending;
  }

  async function accessToken(id: string, key: string): Promise<string | null> {
    const now = Date.now();
    if (token && token.expiresAt > now) return token.value;
    const response = await call(`${IDENTITY}/connect/token`, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api.push',
        client_id: `installation.${id}`,
        client_secret: key,
      }).toString(),
    });
    const body = (await response?.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
    if (!body?.access_token) return null;
    // Renewed at half its lifetime.
    token = { value: body.access_token, expiresAt: now + Math.max(60, Number(body.expires_in) || 3600) * 500 };
    return token.value;
  }

  async function relay(path: string, body: (installationId: string) => unknown): Promise<void> {
    const credentials = await installation();
    if (!credentials) return;
    const bearer = await accessToken(credentials.id, credentials.key);
    if (!bearer) return;
    await call(`${RELAY}${path}`, {
      method: 'POST',
      headers: { accept: 'application/json', authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
      body: JSON.stringify(body(credentials.id)),
    });
  }

  const post = (event: PushEvent, pushUuid: string | null) =>
    relay('/push/send', () => ({
      userId: event.userId,
      organizationId: null,
      deviceId: pushUuid,
      identifier: event.deviceIdentifier ?? null,
      type: event.type,
      payload: payloadOf(event, new Date().toISOString()),
      clientType: null,
      installationId: null,
    }));

  async function send(event: PushEvent): Promise<void> {
    const devices = await findPushDevices(db, event.userId);
    if (!devices.some((device) => device.registered)) return;
    const acting = event.deviceIdentifier ? devices.find((device) => device.identifier === event.deviceIdentifier) : undefined;
    await post(event, acting?.pushUuid ?? null);
  }

  const forget = (pushUuid: string) => relay('/push/delete', () => ({ id: pushUuid }));

  return {
    register(device) {
      runInBackground(
        relay('/push/register', (installationId) => ({
          deviceId: device.pushUuid,
          pushToken: device.pushToken,
          userId: device.userId,
          type: device.type,
          identifier: device.identifier,
          installationId,
        })),
      );
    },
    unregister(pushUuid) {
      if (pushUuid) runInBackground(forget(pushUuid));
    },
    notify(event) {
      runInBackground(send(event));
    },
    signOut(userId, pushUuids) {
      if (!pushUuids.length) return;
      runInBackground(
        (async () => {
          await post({ type: PushType.LogOut, userId }, null);
          await Promise.all(pushUuids.map(forget));
        })(),
      );
    },
  };
}
