import { waitUntil as vercelWaitUntil } from '@vercel/functions';

// Keep the function instance alive until `promise` settles (Vercel), or just
// let it run in the background when served by a long-lived Node process.
export function runInBackground(promise: Promise<unknown>): void {
  const guarded = promise.catch((error) => {
    console.error('Background task failed:', error);
  });
  try {
    vercelWaitUntil(guarded);
  } catch {
    // Not running inside a Vercel request context; the process stays alive anyway.
  }
}
