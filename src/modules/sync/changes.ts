import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { touchRevisionDate } from '../accounts/repo';
import { touchMemberRevisions } from '../organizations/repo';
import type { PushEvent, PushType } from '../push/service';

// A change to data that clients keep: who has to sync it, and what their
// apps are told.
export interface Change {
  // Beyond the caller: the confirmed members of these organizations, and
  // these users.
  orgIds?: Array<string | null>;
  userIds?: string[];
  push: { type: PushType; item?: PushEvent['item'] };
}

// Who makes the change: a signed-in user, or someone opening a Send on its
// owner's behalf. The device making it needs no telling.
export type Changer = { user: { id: string }; device: string | null };

// Runs `write` in one transaction that also moves the revision date of
// everyone who sees the change, so their clients sync; then tells their
// apps.
export async function commit<T>(deps: Deps, caller: Changer, now: string, change: Change, write: (tx: Executor) => Promise<T>): Promise<T> {
  const notified = new Set([caller.user.id, ...(change.userIds ?? [])]);
  const result = await deps.db.transaction().execute(async (tx) => {
    const value = await write(tx);
    for (const userId of notified) await touchRevisionDate(tx, userId, now);
    for (const orgId of new Set(change.orgIds)) {
      if (!orgId) continue;
      for (const userId of await touchMemberRevisions(tx, orgId, now)) notified.add(userId);
    }
    return value;
  });
  for (const userId of notified) deps.push.notify({ ...change.push, userId, deviceIdentifier: caller.device });
  return result;
}
