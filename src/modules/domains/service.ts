import type { Caller } from '../../http/authenticate';
import type { Deps } from '../../main/deps';
import type { Executor } from '../../platform/db';
import { touchRevisionDate } from '../accounts/repo';
import { findDomainSettings, saveDomainSettings } from './repo';
import { buildDomainsResponse, customRulesToActiveEquivalentDomains } from './rules';
import type { DomainsInput } from './schemas';

// Sync leaves out the global groups the user turned off.
export async function domainsJson(db: Executor, userId: string, options: { omitExcludedGlobals?: boolean } = {}) {
  const { customRules, excludedGlobals } = await findDomainSettings(db, userId);
  return buildDomainsResponse(customRulesToActiveEquivalentDomains(customRules), customRules, excludedGlobals, options);
}

export async function updateDomains(deps: Deps, caller: Caller, input: DomainsInput) {
  const userId = caller.user.id;
  const date = new Date().toISOString();
  await deps.db.transaction().execute(async (tx) => {
    const current = await findDomainSettings(tx, userId);
    await saveDomainSettings(
      tx,
      userId,
      { customRules: input.customRules ?? current.customRules, excludedGlobals: input.excludedGlobals ?? current.excludedGlobals },
      date,
    );
    await touchRevisionDate(tx, userId, date);
  });
  return domainsJson(deps.db, userId);
}
