import type { Executor } from '../../platform/db';
import type { CustomEquivalentDomain } from '../../types';
import { normalizeCustomEquivalentDomains } from './rules';

// A user's own equivalent-domain rules, and the global groups they turned off.
export interface DomainSettings {
  customRules: CustomEquivalentDomain[];
  excludedGlobals: number[];
}

export async function findDomainSettings(db: Executor, userId: string): Promise<DomainSettings> {
  const row = await db
    .selectFrom('users')
    .select(['custom_domains', 'excluded_global_domains'])
    .where('id', '=', userId)
    .executeTakeFirst();
  return {
    customRules: normalizeCustomEquivalentDomains(row?.custom_domains ?? []),
    excludedGlobals: row?.excluded_global_domains ?? [],
  };
}

export async function saveDomainSettings(db: Executor, userId: string, settings: DomainSettings, date: string): Promise<void> {
  await db
    .updateTable('users')
    .set({
      custom_domains: JSON.stringify(settings.customRules),
      excluded_global_domains: settings.excludedGlobals,
      updated_at: date,
    })
    .where('id', '=', userId)
    .execute();
}
