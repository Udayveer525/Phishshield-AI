/**
 * Shared data model for the PhishShield detection engine, the extension and the API.
 *
 * Design rules encoded here:
 *  - `score` is a heuristic risk score (0-100), NOT a calibrated probability.
 *  - Only a verified threat-intelligence match may produce `confirmed_malicious`.
 *  - `no_known_threats` means "nothing found", never "safe".
 */

export const VERDICTS = [
  'no_known_threats',
  'suspicious',
  'likely_phishing',
  'confirmed_malicious',
  'inconclusive',
] as const;
export type Verdict = (typeof VERDICTS)[number];

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';

/** Where a piece of evidence came from. The UI keeps these visually separate. */
export type SignalSource = 'local_url' | 'local_content' | 'local_file' | 'reputation' | 'registry' | 'ai';

/**
 * contextual: only meaningful alongside other evidence (e.g. plain HTTP). Never counts alone.
 * weak / moderate / strong: increasing evidential value of a single indicator.
 */
export type SignalStrength = 'contextual' | 'weak' | 'moderate' | 'strong';

export type SignalCategory =
  | 'impersonation'
  | 'obfuscation'
  | 'infrastructure'
  | 'credential_harvest'
  | 'social_engineering'
  | 'payment_fraud'
  | 'evasion'
  | 'threat_intel'
  | 'informational';

export interface Signal {
  /** Stable rule identifier, e.g. `url.ip_host`. */
  id: string;
  source: SignalSource;
  category: SignalCategory;
  strength: SignalStrength;
  /** Contribution to the heuristic score, 0..1. */
  weight: number;
  title: string;
  detail: string;
  /** Raw technical evidence shown in the expandable section. */
  evidence?: string[];
}

export type ProviderStatus = 'match' | 'no_match' | 'error' | 'timeout' | 'unconfigured' | 'skipped';

export interface ReputationFinding {
  providerId: string;
  providerName: string;
  status: ProviderStatus;
  /** Provider-native threat labels, e.g. SOCIAL_ENGINEERING. */
  threatTypes?: string[];
  matchType?: 'exact_url' | 'url_prefix' | 'host';
  /** Epoch ms when the provider was queried (or when the feed snapshot was fetched). */
  checkedAt: number;
  /** For list-based providers: when the underlying dataset was last refreshed. */
  datasetUpdatedAt?: number;
  fromCache?: boolean;
  message?: string;
  /** Multi-engine providers (VirusTotal): how many engines flagged the item in the last analysis. */
  detections?: EngineDetections;
}

export interface EngineDetections {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  /** Engines that returned a result (excludes timeouts and unsupported types). */
  total: number;
}

/** Registration data for a registrable domain, from the registry's RDAP service. */
export interface DomainInfo {
  domain: string;
  status: 'found' | 'not_found' | 'unsupported' | 'error' | 'timeout';
  /** Epoch ms of the registry "registration" event. */
  registeredAt?: number;
  expiresAt?: number;
  registrar?: string;
  source: 'rdap';
  checkedAt: number;
  message?: string;
}

/** A public breach of the site's organisation, from the Have I Been Pwned catalogue. Context only, never a phishing signal. */
export interface BreachRecord {
  name: string;
  title: string;
  domain: string;
  /** YYYY-MM-DD as published by HIBP. */
  breachDate: string;
  pwnCount: number;
  dataClasses: string[];
  isVerified: boolean;
}

export type ReputationStatus = 'checked' | 'partial' | 'unavailable' | 'not_configured' | 'skipped' | 'pending';

export interface ReputationSummary {
  status: ReputationStatus;
  findings: ReputationFinding[];
  note?: string;
  /** Domain registration data (RDAP). Absent when not looked up. */
  domain?: DomainInfo;
  /** Known breaches of this domain's organisation (HIBP). Absent when not looked up. */
  breaches?: BreachRecord[];
}

export const AI_TACTICS = [
  'credential_theft',
  'fake_login',
  'account_suspension_threat',
  'kyc_update_scam',
  'brand_impersonation',
  'authority_impersonation',
  'artificial_urgency',
  'threat_or_intimidation',
  'payment_request',
  'deceptive_offer',
  'remote_access_request',
  'otp_or_pin_request',
  'delivery_scam',
  'job_or_task_scam',
  'investment_scam',
  'digital_arrest_scam',
  'prompt_injection',
  'other',
] as const;
export type AiTactic = (typeof AI_TACTICS)[number];

export interface AiTacticFinding {
  tactic: AiTactic;
  explanation: string;
  /** Quote from the analysed content. */
  evidenceQuote: string;
  /** True when the quote was found verbatim in the submitted content. */
  grounded: boolean;
}

export interface AiAnalysis {
  status: 'ok' | 'unavailable' | 'error' | 'refused' | 'timeout' | 'rate_limited';
  provider?: string;
  model?: string;
  /** The model's contextual concern level. Never a verdict on its own. */
  concern?: 'low' | 'medium' | 'high';
  summaryEn?: string;
  summaryHi?: string;
  tactics?: AiTacticFinding[];
  impersonatedBrand?: string | null;
  advice?: string[];
  injectionAttemptDetected?: boolean;
  message?: string;
  analyzedAt?: number;
}

export interface RiskAssessment {
  input: string;
  /** Normalised URL without fragment. Empty string when unparseable. */
  url: string;
  host: string;
  /** Unicode rendering of the host when it uses punycode. */
  displayHost: string;
  registrableDomain: string | null;
  verdict: Verdict;
  severity: Severity;
  /** Heuristic 0-100 risk score. Not a probability. */
  score: number;
  headline: string;
  recommendedAction: string;
  signals: Signal[];
  reputation: ReputationSummary;
  ai?: AiAnalysis;
  limitations: string[];
  /** Which analysis layers contributed. */
  layers: { localUrl: boolean; localContent: boolean; reputation: boolean; ai: boolean };
  analyzedAt: number;
  engineVersion: string;
}

/** Minimal, privacy-preserving snapshot of a page used for content analysis. */
export interface PageSnapshot {
  url: string;
  title: string;
  /** Visible text only, truncated. Never contains form field values. */
  text: string;
  metaDescription?: string;
  forms: FormSummary;
  truncated: boolean;
}

export interface FormSummary {
  formCount: number;
  passwordFields: number;
  otpFields: number;
  cardFields: number;
  identityFields: number;
  pinFields: number;
  /** Hostnames that forms submit to (no paths, no values). */
  actionHosts: string[];
}

export const EMPTY_FORMS: FormSummary = {
  formCount: 0,
  passwordFields: 0,
  otpFields: 0,
  cardFields: 0,
  identityFields: 0,
  pinFields: 0,
  actionHosts: [],
};
