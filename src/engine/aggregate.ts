import type {
  AiAnalysis,
  ReputationFinding,
  ReputationSummary,
  RiskAssessment,
  Severity,
  Signal,
  Verdict,
} from '../shared/types.js';
import type { ParsedUrl } from './url.js';

export const ENGINE_VERSION = '0.2.0';

/** Total share of the score that AI-derived signals may contribute. AI can add context, never decide. */
export const AI_WEIGHT_CAP = 0.3;

export const THRESHOLDS = {
  suspicious: 30,
  likelyPhishing: 60,
} as const;

export interface AggregateInput {
  input: string;
  parsed: ParsedUrl | null;
  signals: Signal[];
  reputation?: ReputationSummary;
  ai?: AiAnalysis;
  limitations?: string[];
  /** Set when the target cannot be meaningfully assessed. */
  inconclusiveReason?: string;
  /** Destination is hidden (shortener) and nothing else was found. */
  destinationUnknown?: boolean;
  now?: number;
}

export interface ScoreBreakdown {
  score: number;
  strongCount: number;
  moderateCount: number;
  effective: Array<{ id: string; weight: number }>;
}

/**
 * Combine signal weights with diminishing returns: score = 1 - Π(1 - w).
 * - Contextual signals only count when at least one real indicator (weak or stronger) is present.
 * - AI signals are pooled and capped at AI_WEIGHT_CAP.
 * - A verified reputation match (weight 1) saturates the score; the verdict rules decide confirmation.
 */
export function computeScore(signals: Signal[]): ScoreBreakdown {
  const local = signals.filter((s) => s.source !== 'ai');
  const ai = signals.filter((s) => s.source === 'ai');
  const hasRealIndicator = local.some((s) => s.strength !== 'contextual' && s.weight >= 0.1);

  const effective: Array<{ id: string; weight: number }> = [];
  let remaining = 1;
  for (const s of local) {
    const w = s.strength === 'contextual' && !hasRealIndicator ? 0 : clamp01(s.weight);
    if (w > 0) effective.push({ id: s.id, weight: w });
    remaining *= 1 - w;
  }
  let aiRemaining = 1;
  for (const s of ai) aiRemaining *= 1 - clamp01(s.weight);
  const aiWeight = Math.min(AI_WEIGHT_CAP, 1 - aiRemaining);
  if (aiWeight > 0) effective.push({ id: 'ai.pooled', weight: aiWeight });
  remaining *= 1 - aiWeight;

  return {
    score: Math.round((1 - remaining) * 100),
    strongCount: local.filter((s) => s.strength === 'strong').length,
    moderateCount: local.filter((s) => s.strength === 'moderate').length,
    effective,
  };
}

export function decideVerdict(
  breakdown: ScoreBreakdown,
  opts: { reputationMatch: boolean; inconclusiveReason?: string; destinationUnknown?: boolean },
): Verdict {
  if (opts.reputationMatch) return 'confirmed_malicious';
  if (opts.inconclusiveReason) return 'inconclusive';
  const { score, strongCount, moderateCount } = breakdown;
  // "likely phishing" requires independent local evidence: one strong indicator, or several moderate ones.
  if (score >= THRESHOLDS.likelyPhishing && (strongCount >= 1 || moderateCount >= 3)) return 'likely_phishing';
  if (score >= THRESHOLDS.suspicious) return 'suspicious';
  if (opts.destinationUnknown) return 'inconclusive';
  return 'no_known_threats';
}

export function severityFor(verdict: Verdict, score: number): Severity {
  switch (verdict) {
    case 'confirmed_malicious':
      return 'critical';
    case 'likely_phishing':
      return 'high';
    case 'suspicious':
      return score >= 45 ? 'medium' : 'low';
    case 'inconclusive':
      return 'unknown';
    default:
      return 'info';
  }
}

export const RECOMMENDED_ACTIONS: Record<Verdict, string> = {
  confirmed_malicious:
    'Leave this site now. Do not enter passwords, OTPs, card or UPI details. If you already did, contact your bank immediately and report at cybercrime.gov.in or call 1930.',
  likely_phishing:
    'Do not sign in or pay here. Open the organisation’s official app or type its address yourself instead of using this link.',
  suspicious:
    'Be careful. Verify the website address before entering any personal or payment information.',
  no_known_threats:
    'No known threats were found, but that is not a guarantee of safety. Stay alert for unexpected requests for OTPs, passwords or payments.',
  inconclusive:
    'PhishShield could not fully assess this link. Treat it with caution and check the address before entering information.',
};

const VERDICT_PREFIX: Record<Verdict, string> = {
  confirmed_malicious: 'Known dangerous site',
  likely_phishing: 'Likely phishing',
  suspicious: 'Suspicious',
  no_known_threats: 'No known threats found',
  inconclusive: 'Could not fully check',
};

export function aggregate(input: AggregateInput): RiskAssessment {
  const now = input.now ?? Date.now();
  const reputation: ReputationSummary = input.reputation ?? { status: 'not_configured', findings: [] };
  // A listed URL (or listed parent path) is a verified match. A listed *host* with a different
  // path is strong evidence but not confirmation: compromised legitimate sites are common.
  const matches = reputation.findings.filter((f) => f.status === 'match');
  const verified = matches.filter((f) => f.matchType !== 'host');
  const reputationMatch = verified.length > 0;

  const signals = [...input.signals];
  for (const m of matches.filter((f) => f.matchType === 'host')) {
    signals.unshift({
      id: `intel.${m.providerId}.host`,
      source: 'reputation',
      category: 'threat_intel',
      strength: 'strong',
      weight: 0.5,
      title: `This website appears in ${m.providerName}`,
      detail: `${m.providerName} lists other pages on ${input.parsed?.host ?? 'this host'} as phishing. This exact page is not listed, so this is strong evidence rather than confirmation.`,
      evidence: [`provider: ${m.providerName}`, 'match: host', `checked: ${new Date(m.checkedAt).toISOString()}`],
    });
  }
  for (const m of verified) {
    signals.unshift({
      id: `intel.${m.providerId}`,
      source: 'reputation',
      category: 'threat_intel',
      strength: 'strong',
      weight: 1,
      title: `Listed by ${m.providerName}`,
      detail: `${m.providerName} reports this ${m.matchType === 'host' ? 'website' : 'address'} as ${formatThreatTypes(m.threatTypes)}.`,
      evidence: [
        `provider: ${m.providerName}`,
        `match: ${m.matchType ?? 'exact_url'}`,
        ...(m.threatTypes?.length ? [`threat types: ${m.threatTypes.join(', ')}`] : []),
        `checked: ${new Date(m.checkedAt).toISOString()}`,
        ...(m.datasetUpdatedAt ? [`dataset updated: ${new Date(m.datasetUpdatedAt).toISOString()}`] : []),
      ],
    });
  }

  for (const f of reputation.findings) {
    const minority = minorityDetectionSignal(f, 'address');
    if (minority) signals.unshift(minority);
  }

  const breakdown = computeScore(signals);
  const verdict = decideVerdict(breakdown, {
    reputationMatch,
    inconclusiveReason: input.inconclusiveReason,
    destinationUnknown: input.destinationUnknown,
  });
  const score = reputationMatch ? 100 : breakdown.score;

  // Contextual signals that did not count are kept for transparency but shown with zero weight.
  const counted = new Set(breakdown.effective.map((e) => e.id));
  const ranked = rankSignals(
    signals.map((s) => (s.strength === 'contextual' && s.source !== 'ai' && !counted.has(s.id) ? { ...s, weight: 0 } : s)),
  );
  const top = ranked.find((s) => s.weight > 0 && s.category !== 'informational');
  let headline = VERDICT_PREFIX[verdict];
  if (verdict === 'inconclusive' && input.inconclusiveReason) headline = `${headline}: ${input.inconclusiveReason}`;
  else if (verdict !== 'no_known_threats' && top) headline = `${headline}: ${top.title}`;

  const limitations = [...(input.limitations ?? [])];
  const hasContent = signals.some((s) => s.source === 'local_content') || (input.limitations ?? []).some((l) => l.startsWith('Page content'));
  if (!hasContent) limitations.push('Only the web address was checked. Run “Analyze page” to inspect what the page asks you to do.');
  if (reputation.status === 'not_configured') limitations.push('Reputation services are not configured, so known-bad lists were not consulted.');
  if (reputation.status === 'unavailable') limitations.push('Reputation services could not be reached; known-bad lists were not consulted.');
  if (reputation.status === 'pending') limitations.push('Shown before reputation lists finished checking; this result is based on local checks.');
  if (reputation.status === 'partial') limitations.push('Some reputation services did not respond; results may be incomplete.');
  if (verdict === 'no_known_threats') limitations.push('“No known threats” is not proof of safety. New phishing sites often appear before any list includes them.');
  if (breakdown.effective.some((e) => e.id === 'ai.pooled')) limitations.push('AI findings add context only. They are capped and can never confirm a site as malicious.');

  return {
    input: input.input,
    url: input.parsed?.href ?? '',
    host: input.parsed?.host ?? '',
    displayHost: input.parsed?.unicodeHost ?? input.parsed?.host ?? '',
    registrableDomain: input.parsed?.registrableDomain ?? null,
    verdict,
    severity: severityFor(verdict, score),
    score,
    headline,
    recommendedAction: RECOMMENDED_ACTIONS[verdict],
    signals: ranked,
    reputation,
    ai: input.ai,
    limitations: [...new Set(limitations)],
    layers: {
      localUrl: signals.some((s) => s.source === 'local_url') || !!input.parsed,
      localContent: hasContent,
      reputation: reputation.status === 'checked' || reputation.status === 'partial',
      ai: input.ai?.status === 'ok',
    },
    analyzedAt: now,
    engineVersion: ENGINE_VERSION,
  };
}

/** Engines that must flag a file or URL before PhishShield treats a multi-engine result as confirmed. */
export const MULTI_ENGINE_CONFIRM = 3;

/** Signal for a multi-engine (VirusTotal) result that is below the confirmation bar. */
export function minorityDetectionSignal(f: ReputationFinding, subject: 'file' | 'address'): Signal | null {
  const d = f.detections;
  if (!d || f.status === 'match') return null;
  const flagged = d.malicious + d.suspicious;
  if (flagged === 0) return null;
  return {
    id: `intel.${f.providerId}.minority`,
    source: 'reputation',
    category: 'threat_intel',
    strength: d.malicious > 0 ? 'moderate' : 'weak',
    weight: d.malicious >= 2 ? 0.3 : d.malicious === 1 ? 0.2 : 0.1,
    title: `${flagged} of ${d.total} security vendors flagged this ${subject}`,
    detail: `A small number of ${f.providerName} engines report this ${subject} as malicious or suspicious. That is a warning sign, not confirmation: single-engine detections are sometimes false positives.`,
    evidence: [`provider: ${f.providerName}`, `malicious: ${d.malicious}`, `suspicious: ${d.suspicious}`, `harmless: ${d.harmless}`, `undetected: ${d.undetected}`],
  };
}

const STRENGTH_ORDER = { strong: 3, moderate: 2, weak: 1, contextual: 0 } as const;
const SOURCE_ORDER = { reputation: 3, local_url: 2, local_content: 2, local_file: 2, registry: 2, ai: 1 } as const;

export function rankSignals(signals: Signal[]): Signal[] {
  return [...signals].sort(
    (a, b) =>
      SOURCE_ORDER[b.source] - SOURCE_ORDER[a.source] ||
      STRENGTH_ORDER[b.strength] - STRENGTH_ORDER[a.strength] ||
      b.weight - a.weight,
  );
}

export function formatThreatTypes(types?: string[]): string {
  if (!types?.length) return 'malicious';
  const map: Record<string, string> = {
    SOCIAL_ENGINEERING: 'phishing / social engineering',
    MALWARE: 'malware',
    UNWANTED_SOFTWARE: 'unwanted software',
    POTENTIALLY_HARMFUL_APPLICATION: 'potentially harmful apps',
    PHISHING: 'phishing',
  };
  return types.map((t) => map[t] ?? t.toLowerCase()).join(', ');
}

function clamp01(n: number): number {
  return Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0;
}
