import type { Executor } from '../../platform/db';
import type { CustomEquivalentDomain } from '../../types';
import { customRulesToActiveEquivalentDomains, normalizeCustomEquivalentDomains, normalizeEquivalentDomains } from './rules';

// A user's own equivalent-domain rules, and the global groups they turned off.
export interface DomainSettings {
  customRules: CustomEquivalentDomain[];
  excludedGlobals: number[];
}

function parseList(raw: string | null | undefined): unknown[] {
  try {
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export async function findDomainSettings(db: Executor, userId: string): Promise<DomainSettings> {
  const row = await db
    .selectFrom('domain_settings')
    .select(['equivalent_domains', 'custom_equivalent_domains', 'excluded_global_equivalent_domains'])
    .where('user_id', '=', userId)
    .executeTakeFirst();
  const customRules = normalizeCustomEquivalentDomains(parseList(row?.custom_equivalent_domains));
  return {
    // Rows written before the rules were kept hold only the active groups.
    customRules: customRules.length
      ? customRules
      : normalizeCustomEquivalentDomains(normalizeEquivalentDomains(parseList(row?.equivalent_domains))),
    excludedGlobals: parseList(row?.excluded_global_equivalent_domains).filter((type): type is number => Number.isInteger(type)),
  };
}

// The active groups are stored next to the rules for the backup format.
export async function saveDomainSettings(db: Executor, userId: string, settings: DomainSettings, date: string): Promise<void> {
  const values = {
    equivalent_domains: JSON.stringify(customRulesToActiveEquivalentDomains(settings.customRules)),
    custom_equivalent_domains: JSON.stringify(settings.customRules),
    excluded_global_equivalent_domains: JSON.stringify(settings.excludedGlobals),
    updated_at: date,
  };
  await db
    .insertInto('domain_settings')
    .values({ user_id: userId, ...values })
    .onConflict((oc) => oc.column('user_id').doUpdateSet(values))
    .execute();
}
