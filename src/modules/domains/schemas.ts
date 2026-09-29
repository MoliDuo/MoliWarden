import { z } from 'zod';
import { normalizeCustomEquivalentDomains, normalizeEquivalentDomains, normalizeExcludedGlobalTypes } from './rules';

// Each field left out keeps its current value.
export const domainsBody = z
  .object({
    equivalentDomains: z.unknown().optional(),
    customEquivalentDomains: z.unknown().optional(),
    excludedGlobalEquivalentDomains: z.unknown().optional(),
    // Some clients send the excluded global types under this name.
    globalEquivalentDomains: z.unknown().optional(),
  })
  .transform((body) => {
    const excluded = body.excludedGlobalEquivalentDomains ?? body.globalEquivalentDomains;
    const custom =
      body.customEquivalentDomains !== undefined
        ? body.customEquivalentDomains
        : body.equivalentDomains !== undefined
          ? normalizeEquivalentDomains(body.equivalentDomains)
          : undefined;
    return {
      customRules: custom === undefined ? undefined : normalizeCustomEquivalentDomains(custom),
      excludedGlobals: excluded === undefined ? undefined : normalizeExcludedGlobalTypes(excluded),
    };
  });
export type DomainsInput = z.output<typeof domainsBody>;
