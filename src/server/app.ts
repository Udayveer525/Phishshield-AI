import type { IncomingMessage, ServerResponse } from 'node:http';
import { z } from 'zod';
import type { AiService } from './ai/service.js';
import type { IntelService } from './intel/service.js';
import type { ProviderResult } from './intel/types.js';
import type { VtFileInfo } from './intel/virustotal.js';
import { RateLimiter } from './util.js';

export const MAX_BODY_BYTES = 48 * 1024;

const UrlField = z.string().min(1).max(4096);

export const ReputationRequest = z.object({ url: UrlField, deep: z.boolean().optional() }).strict();

/** Only a SHA-256 hash is accepted: file contents never reach the server. */
export const FileRequest = z.object({ sha256: z.string().regex(/^[a-fA-F0-9]{64}$/, 'must be a hex SHA-256') }).strict();

export interface FileReputation {
  readonly configured: boolean;
  lookupFile(sha256: string): Promise<{ finding: ProviderResult; file?: VtFileInfo }>;
}

export const AnalyzeRequest = z
  .object({
    kind: z.enum(['page', 'message']).default('page'),
    url: UrlField.optional(),
    title: z.string().max(500).optional(),
    text: z.string().max(12_000),
    forms: z
      .object({
        formCount: z.number().int().min(0).max(1000),
        passwordFields: z.number().int().min(0).max(1000),
        otpFields: z.number().int().min(0).max(1000),
        cardFields: z.number().int().min(0).max(1000),
        identityFields: z.number().int().min(0).max(1000),
        pinFields: z.number().int().min(0).max(1000),
        actionHosts: z.array(z.string().max(253)).max(20),
      })
      .partial()
      .optional(),
    localFindings: z.array(z.string().max(200)).max(30).optional(),
  })
  .strict();

export interface AppDeps {
  intel: IntelService;
  ai: AiService;
  files?: FileReputation;
  allowedOrigins: string[];
  version: string;
  now?: () => number;
  log?: (line: string) => void;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

export function createApp(deps: AppDeps) {
  const now = deps.now ?? Date.now;
  const limits = {
    reputation: new RateLimiter(60, 60, now),
    analyze: new RateLimiter(6, 6, now),
    file: new RateLimiter(10, 10, now),
    health: new RateLimiter(30, 30, now),
  };
  let aiInFlight = 0;
  const MAX_AI_CONCURRENCY = 4;

  function originAllowed(origin: string | undefined): boolean {
    if (!origin) return true; // non-browser clients (curl, tests); still rate-limited
    if (deps.allowedOrigins.length) return deps.allowedOrigins.includes(origin);
    return /^chrome-extension:\/\/[a-p]{32}$/.test(origin) || /^moz-extension:\/\/[0-9a-f-]{36}$/.test(origin);
  }

  function baseHeaders(origin: string | undefined): Record<string, string> {
    const h: Record<string, string> = {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'cross-origin-resource-policy': 'same-site',
      vary: 'Origin',
    };
    if (origin && originAllowed(origin)) {
      h['access-control-allow-origin'] = origin;
      h['access-control-allow-methods'] = 'GET, POST, OPTIONS';
      h['access-control-allow-headers'] = 'content-type';
      h['access-control-max-age'] = '600';
    }
    return h;
  }

  function limit(bucket: keyof typeof limits, key: string): void {
    const wait = limits[bucket].take(key);
    if (wait > 0) throw new HttpError(429, 'rate_limited', 'Too many requests. Please slow down.', { 'retry-after': String(wait) });
  }

  async function readJson(req: IncomingMessage): Promise<unknown> {
    const type = req.headers['content-type'] ?? '';
    if (!/^application\/json\b/i.test(type)) throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json.');
    const declared = Number(req.headers['content-length'] ?? '0');
    if (declared > MAX_BODY_BYTES) throw new HttpError(413, 'payload_too_large', 'Request body too large.');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > MAX_BODY_BYTES) throw new HttpError(413, 'payload_too_large', 'Request body too large.');
      chunks.push(chunk as Buffer);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new HttpError(400, 'invalid_json', 'Body is not valid JSON.');
    }
  }

  function parse<T>(schema: z.ZodType<T>, body: unknown): T {
    const r = schema.safeParse(body);
    if (!r.success) {
      const issue = r.error.issues[0];
      throw new HttpError(400, 'invalid_request', `Invalid request${issue ? `: ${issue.path.join('.') || 'body'} ${issue.message}` : ''}.`);
    }
    return r.data;
  }

  async function withAiSlot<T>(fn: () => Promise<T>): Promise<T> {
    if (aiInFlight >= MAX_AI_CONCURRENCY) throw new HttpError(503, 'busy', 'AI analysis is busy. Try again in a moment.', { 'retry-after': '5' });
    aiInFlight++;
    try {
      return await fn();
    } finally {
      aiInFlight--;
    }
  }

  async function route(req: IncomingMessage, client: string): Promise<{ status: number; body: unknown }> {
    const path = (req.url ?? '/').split('?')[0];
    const method = req.method ?? 'GET';

    if (path === '/v1/health' && method === 'GET') {
      limit('health', client);
      return {
        status: 200,
        body: {
          service: 'phishshield-api',
          version: deps.version,
          providers: deps.intel.providers().map((p) => ({ id: p.id, name: p.name, configured: p.configured, ...p.details })),
          ai: { configured: deps.ai.configured, provider: deps.ai.provider, model: deps.ai.model },
          features: { fileReputation: Boolean(deps.files?.configured) },
          privacy:
            'Request bodies are not logged or stored. URLs are sent to configured reputation providers without query strings; only the registrable domain is sent to its registry (RDAP); files are looked up by SHA-256 only and never uploaded.',
        },
      };
    }
    if (path === '/v1/reputation' && method === 'POST') {
      limit('reputation', client);
      const { url, deep } = parse(ReputationRequest, await readJson(req));
      return { status: 200, body: await deps.intel.check(url, { deep }) };
    }
    if (path === '/v1/file' && method === 'POST') {
      limit('file', client);
      const { sha256 } = parse(FileRequest, await readJson(req));
      if (!deps.files) {
        return { status: 200, body: { finding: { providerId: 'virustotal', providerName: 'VirusTotal', status: 'unconfigured', checkedAt: now(), message: 'File reputation is not configured on the server.' } } };
      }
      const { finding, file } = await deps.files.lookupFile(sha256.toLowerCase());
      const { cacheTtlSec: _ttl, ...wire } = finding;
      return { status: 200, body: { finding: wire, ...(file ? { file } : {}) } };
    }
    if (path === '/v1/analyze' && method === 'POST') {
      limit('analyze', client);
      const input = parse(AnalyzeRequest, await readJson(req));
      const ai = await withAiSlot(() => deps.ai.analyze(input));
      return { status: 200, body: ai };
    }
    if (['/v1/health', '/v1/reputation', '/v1/analyze', '/v1/file'].includes(path ?? '')) {
      throw new HttpError(405, 'method_not_allowed', 'Method not allowed.');
    }
    throw new HttpError(404, 'not_found', 'Not found.');
  }

  return async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = now();
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
    const headers = baseHeaders(origin);
    const client = req.socket.remoteAddress ?? 'unknown';
    let status = 500;
    try {
      if (!originAllowed(origin)) throw new HttpError(403, 'origin_not_allowed', 'Origin not allowed.');
      if (req.method === 'OPTIONS') {
        status = 204;
        res.writeHead(204, headers).end();
        return;
      }
      const out = await route(req, client);
      status = out.status;
      res.writeHead(status, headers).end(JSON.stringify(out.body));
    } catch (err) {
      const e = err instanceof HttpError ? err : new HttpError(500, 'internal_error', 'Internal server error.');
      status = e.status;
      if (!(err instanceof HttpError)) console.error('[phishshield] unhandled error', err instanceof Error ? err.message : err);
      res.writeHead(e.status, { ...headers, ...e.headers }).end(JSON.stringify({ error: e.code, message: e.message }));
    } finally {
      // Only metadata is logged: never URLs, page text or messages.
      deps.log?.(`${req.method} ${(req.url ?? '').split('?')[0]} ${status} ${now() - started}ms`);
    }
  };
}
