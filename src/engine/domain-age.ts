import type { DomainInfo, Signal } from '../shared/types.js';

const DAY = 86_400_000;

/**
 * Age bands for a domain's registration date. Most phishing domains are used within days of
 * registration and abandoned within weeks, so a very young domain is meaningful evidence; an old
 * one is not evidence of safety (compromised legitimate sites host phishing too). Weights are set
 * so that a young domain alone stays below the "suspicious" threshold: it only adds to other signs.
 */
export const DOMAIN_AGE_BANDS = [
  { maxDays: 7, id: 'registry.domain_days_old', strength: 'moderate', weight: 0.26 },
  { maxDays: 30, id: 'registry.domain_weeks_old', strength: 'moderate', weight: 0.16 },
  { maxDays: 90, id: 'registry.domain_months_old', strength: 'contextual', weight: 0.06 },
] as const;

export function domainAgeDays(info: DomainInfo, now = Date.now()): number | null {
  if (info.status !== 'found' || !info.registeredAt || !Number.isFinite(info.registeredAt)) return null;
  // A registration date in the future is a data error; ignore it rather than guess.
  if (info.registeredAt > now + DAY) return null;
  return Math.max(0, Math.floor((now - info.registeredAt) / DAY));
}

export function describeAge(days: number): string {
  if (days < 1) return 'today';
  if (days === 1) return '1 day ago';
  if (days < 60) return `${days} days ago`;
  if (days < 730) return `${Math.round(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

/** Signals derived from domain registration data. Pure; returns [] when no usable data. */
export function domainAgeSignals(info: DomainInfo | undefined, now = Date.now()): Signal[] {
  if (!info) return [];
  const days = domainAgeDays(info, now);
  if (days === null) return [];
  const registered = new Date(info.registeredAt!).toISOString().slice(0, 10);
  const evidence = [`domain: ${info.domain}`, `registered: ${registered} (${describeAge(days)})`, ...(info.registrar ? [`registrar: ${info.registrar}`] : []), 'source: registry RDAP'];
  const band = DOMAIN_AGE_BANDS.find((b) => days < b.maxDays);
  if (!band) {
    return [
      {
        id: 'registry.domain_age',
        source: 'registry',
        category: 'informational',
        strength: 'contextual',
        weight: 0,
        title: `Domain registered ${describeAge(days)}`,
        detail: 'An established domain. This is not proof of safety: hacked legitimate sites are also used for phishing.',
        evidence,
      },
    ];
  }
  return [
    {
      id: band.id,
      source: 'registry',
      category: 'infrastructure',
      strength: band.strength,
      weight: band.weight,
      title: days < 30 ? `Brand-new domain: registered ${describeAge(days)}` : `Recently registered domain (${describeAge(days)})`,
      detail:
        days < 30
          ? 'Most phishing sites use domains registered in the last few days or weeks. Real banks and government services rarely use new domains.'
          : 'This domain is only a few months old. On its own that is common, but it adds weight to other warning signs.',
      evidence,
    },
  ];
}
