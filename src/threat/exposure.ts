import type { CategoryExposure, ThreatCategory } from './contracts.js';

export interface ContributionRecord {
  id: string;
  points: number;
  primaryCategory: ThreatCategory;
}

/** Derive an explanatory category score from the existing, unique factor ledger. */
export function categoryExposure(category: ThreatCategory, contributions: Iterable<ContributionRecord>): CategoryExposure {
  const ids = new Set<string>();
  let score = 0;
  for (const contribution of contributions) {
    if (contribution.primaryCategory !== category || ids.has(contribution.id)) continue;
    ids.add(contribution.id);
    score += contribution.points;
  }
  return { category, score: Math.min(100, score), contributionIds: [...ids] };
}
