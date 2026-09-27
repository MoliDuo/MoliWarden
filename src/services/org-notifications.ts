import type { Env } from '../types';
import { runInBackground } from '../platform/background';
import { notifyUserVaultSync } from './notifications';
import { listMemberUserIds } from './storage-org-repo';

// Tell every member of an organization to resync (mobile push relay only;
// other clients pick the change up through the bumped revision date).
export function notifyOrgMembersSync(env: Env, orgId: string, revisionDate: string, contextId?: string | null): void {
  runInBackground(
    listMemberUserIds(env.DB, orgId).then((userIds) => {
      for (const userId of userIds) notifyUserVaultSync(env, userId, revisionDate, contextId ?? null);
    })
  );
}
