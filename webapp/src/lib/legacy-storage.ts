// Removes browser data written under the upstream project's prefix before the
// rename. Nothing is read or migrated: signing in again recreates everything.
// Safe to delete once no browser can still hold such data.
const LEGACY_PREFIX = 'nodewarden';

function purgeStorage(storage: Storage): void {
  const keys: string[] = [];
  for (let index = 0; index < storage.length; index += 1) {
    const key = storage.key(index);
    if (key?.startsWith(LEGACY_PREFIX)) keys.push(key);
  }
  for (const key of keys) storage.removeItem(key);
}

export function purgeLegacyBrowserStorage(): void {
  try {
    purgeStorage(window.localStorage);
    purgeStorage(window.sessionStorage);
  } catch {
    // Storage can be unavailable (private mode, blocked site data).
  }
  try {
    window.indexedDB?.deleteDatabase(`${LEGACY_PREFIX}-web-cache`);
  } catch {
    // Same as above.
  }
  if ('caches' in window) {
    void caches
      .keys()
      .then((names) => Promise.all(names.filter((name) => name.startsWith(LEGACY_PREFIX)).map((name) => caches.delete(name))))
      .catch(() => undefined);
  }
}
