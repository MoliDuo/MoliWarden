import type { Deps } from '../../main/deps';
import { deleteExpiredConsumedTokens } from '../../platform/db/consumed';
import { removeAbandonedUploads } from '../attachments/service';
import { pruneAuditLog } from '../audit/service';
import { deleteExpiredAuthRequests } from '../auth-requests/repo';
import { deleteExpiredRefreshTokens } from '../auth/repo';
import { runScheduledBackups } from '../backup/runs';
import { deleteExpiredChallenges } from '../passkeys/repo';
import { removeExpiredSends } from '../sends/service';
import { deleteExpiredRememberTokens } from '../two-factor/repo';

// The scheduled job: the backups that are due, and removing what has run
// out. Nothing on the request path cleans up; expired rows are refused
// where they are read and only deleted here.

type Task = (deps: Deps, now: Date) => Promise<number>;

const CLEANUP: Record<string, Task> = {
  sessions: (deps, now) => deleteExpiredRefreshTokens(deps.db, now),
  rememberedDevices: (deps, now) => deleteExpiredRememberTokens(deps.db, now),
  passkeyChallenges: (deps, now) => deleteExpiredChallenges(deps.db, now),
  usedTokens: (deps, now) => deleteExpiredConsumedTokens(deps.db, now),
  rateLimits: (deps, now) => deps.limiter.prune(now),
  loginRequests: (deps, now) => deleteExpiredAuthRequests(deps.db, now.getTime()),
  sends: removeExpiredSends,
  abandonedUploads: removeAbandonedUploads,
  auditLog: (deps, now) => pruneAuditLog(deps, now),
};

export interface CronResult {
  // Rows removed per task; a task that failed is listed under `failed`.
  removed: Record<string, number>;
  failed: string[];
}

// Each task runs on its own: one failing does not keep the others from running.
export async function runCron(deps: Deps, now = new Date()): Promise<CronResult> {
  const cleanup = Object.entries(CLEANUP).map(async ([name, task]) => {
    try {
      return { name, removed: await task(deps, now) };
    } catch (error) {
      console.error(`Cleanup task ${name} failed:`, error);
      return { name, removed: null };
    }
  });
  const [, results] = await Promise.all([runScheduledBackups(deps, now), Promise.all(cleanup)]);
  return {
    removed: Object.fromEntries(results.filter((r) => r.removed !== null).map((r) => [r.name, r.removed as number])),
    failed: results.filter((r) => r.removed === null).map((r) => r.name),
  };
}
