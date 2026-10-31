export type AiProviderId = 'groq' | 'anthropic';

export interface ServerConfig {
  host: string;
  port: number;
  /** Exact Origins allowed by CORS, e.g. chrome-extension://<id>. Empty = any chrome-extension origin (dev only). */
  allowedOrigins: string[];
  gsbApiKey?: string;
  openPhishEnabled: boolean;
  openPhishFeedUrl?: string;
  /** VirusTotal API v3 key: URL lookups on manual scans and file-hash lookups. */
  vtApiKey?: string;
  /** Domain registration dates from registry RDAP services. */
  rdapEnabled: boolean;
  /** Have I Been Pwned public breach catalogue (no key needed). */
  hibpBreachesEnabled: boolean;
  hibpUserAgent: string;
  /** Which AI provider to use; null when none is configured. */
  aiProvider: AiProviderId | null;
  groqApiKey?: string;
  groqModel?: string;
  anthropicApiKey?: string;
  anthropicModel?: string;
  /** Anthropic only: server-side model fallback on overload. */
  aiFallbacks: boolean;
  intelTimeoutMs: number;
  aiTimeoutMs: number;
}

function int(v: string | undefined, d: number, min: number, max: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n >= min && n <= max ? Math.floor(n) : d;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  return {
    host: env.HOST || '127.0.0.1',
    port: int(env.PORT, 8787, 1, 65535),
    allowedOrigins: (env.ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    gsbApiKey: env.GSB_API_KEY || undefined,
    openPhishEnabled: (env.OPENPHISH_ENABLED ?? 'true').toLowerCase() !== 'false',
    openPhishFeedUrl: env.OPENPHISH_FEED_URL || undefined,
    vtApiKey: env.VT_API_KEY || undefined,
    rdapEnabled: (env.RDAP_ENABLED ?? 'true').toLowerCase() !== 'false',
    hibpBreachesEnabled: (env.HIBP_BREACHES_ENABLED ?? 'true').toLowerCase() !== 'false',
    hibpUserAgent: env.HIBP_USER_AGENT || 'PhishShield-AI/0.2 (browser security extension backend)',
    aiProvider: resolveAiProvider(env),
    groqApiKey: env.GROQ_API_KEY || undefined,
    groqModel: env.GROQ_MODEL || undefined,
    anthropicApiKey: env.ANTHROPIC_API_KEY || undefined,
    anthropicModel: env.ANTHROPIC_MODEL || undefined,
    aiFallbacks: (env.AI_FALLBACKS ?? 'default') !== 'off',
    intelTimeoutMs: int(env.INTEL_TIMEOUT_MS, 4000, 500, 15000),
    aiTimeoutMs: int(env.AI_TIMEOUT_MS, 30000, 2000, 120000),
  };
}

/** AI_PROVIDER=groq|anthropic|none picks explicitly; otherwise the first provider with a key wins (Groq first). */
function resolveAiProvider(env: NodeJS.ProcessEnv): AiProviderId | null {
  const requested = (env.AI_PROVIDER ?? '').trim().toLowerCase();
  if (requested === 'groq' || requested === 'anthropic') return requested;
  if (requested === 'none' || requested === 'off') return null;
  if (env.GROQ_API_KEY) return 'groq';
  if (env.ANTHROPIC_API_KEY) return 'anthropic';
  return null;
}
