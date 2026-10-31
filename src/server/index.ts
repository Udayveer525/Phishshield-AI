import { createServer } from 'node:http';
import { createAnthropicClient } from './ai/anthropic.js';
import { createGroqClient } from './ai/groq.js';
import { createAiService } from './ai/service.js';
import type { ModelClient } from './ai/types.js';
import { createApp } from './app.js';
import { loadConfig, type ServerConfig } from './config.js';
import { createBreachCatalog } from './intel/hibp.js';
import { createOpenPhishProvider } from './intel/openphish.js';
import { createRdapClient } from './intel/rdap.js';
import { createSafeBrowsingProvider } from './intel/safe-browsing.js';
import { createIntelService } from './intel/service.js';
import { createVirusTotalProvider } from './intel/virustotal.js';

const VERSION = '0.2.0';
const config = loadConfig();

const gsb = createSafeBrowsingProvider({ apiKey: config.gsbApiKey, timeoutMs: config.intelTimeoutMs, clientVersion: VERSION });
const openphish = createOpenPhishProvider({ enabled: config.openPhishEnabled, feedUrl: config.openPhishFeedUrl });
const stopFeed = openphish.start();
const vt = createVirusTotalProvider({ apiKey: config.vtApiKey, timeoutMs: config.intelTimeoutMs + 2000 });
const rdap = createRdapClient({ enabled: config.rdapEnabled });
const breaches = createBreachCatalog({ enabled: config.hibpBreachesEnabled, userAgent: config.hibpUserAgent });
const stopBreaches = breaches.start();

const intel = createIntelService([gsb, openphish, vt], { rdap, breaches });
const ai = createAiService(createModelClient(config));

function createModelClient(c: ServerConfig): ModelClient | null {
  switch (c.aiProvider) {
    case 'groq':
      return createGroqClient({ apiKey: c.groqApiKey, model: c.groqModel, timeoutMs: c.aiTimeoutMs });
    case 'anthropic':
      return createAnthropicClient({ apiKey: c.anthropicApiKey, model: c.anthropicModel, timeoutMs: c.aiTimeoutMs, fallbacks: c.aiFallbacks });
    default:
      return null;
  }
}

const app = createApp({
  intel,
  ai,
  files: { configured: vt.isConfigured(), lookupFile: vt.lookupFile },
  allowedOrigins: config.allowedOrigins,
  version: VERSION,
  log: (line) => console.info(`[phishshield] ${line}`),
});

const server = createServer((req, res) => void app(req, res));
server.requestTimeout = 60_000;
server.headersTimeout = 10_000;
server.listen(config.port, config.host, () => {
  console.info(`[phishshield] API listening on http://${config.host}:${config.port}`);
  console.info(`[phishshield] Google Safe Browsing: ${gsb.isConfigured() ? 'configured' : 'not configured (set GSB_API_KEY)'}`);
  console.info(`[phishshield] OpenPhish feed: ${config.openPhishEnabled ? 'enabled' : 'disabled'}`);
  console.info(`[phishshield] VirusTotal: ${vt.isConfigured() ? 'configured (on-demand URL scans + file hashes)' : 'not configured (set VT_API_KEY)'}`);
  console.info(`[phishshield] Domain age (RDAP): ${config.rdapEnabled ? 'enabled' : 'disabled'} · HIBP breach catalogue: ${config.hibpBreachesEnabled ? 'enabled' : 'disabled'}`);
  console.info(`[phishshield] AI analysis: ${ai.configured ? `${ai.provider} ${ai.model}` : `not configured (set ${config.aiProvider === 'anthropic' ? 'ANTHROPIC_API_KEY' : 'GROQ_API_KEY'})`}`);
  if (!config.allowedOrigins.length) console.warn('[phishshield] ALLOWED_ORIGINS not set: accepting any extension origin (fine for local dev).');
});

function shutdown() {
  stopFeed();
  stopBreaches();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
