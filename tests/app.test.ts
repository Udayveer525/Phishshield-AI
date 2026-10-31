import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAiService } from '../src/server/ai/service.js';
import { MAX_BODY_BYTES, createApp } from '../src/server/app.js';
import { createIntelService } from '../src/server/intel/service.js';

const EXT = `chrome-extension://${'a'.repeat(32)}`;
let server: Server;
let base: string;

beforeAll(async () => {
  const intel = createIntelService([
    {
      id: 'fake',
      name: 'Fake',
      isConfigured: () => true,
      describe: () => ({ note: 'test' }),
      check: async () => ({ providerId: 'fake', providerName: 'Fake', status: 'no_match', checkedAt: 1 }),
    },
  ]);
  const app = createApp({ intel, ai: createAiService(null), allowedOrigins: [], version: 'test' });
  server = createServer((req, res) => void app(req, res));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: EXT, ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

describe('API boundary', () => {
  it('health reports configuration honestly', async () => {
    const r = await fetch(`${base}/v1/health`, { headers: { origin: EXT } });
    expect(r.status).toBe(200);
    expect(r.headers.get('access-control-allow-origin')).toBe(EXT);
    expect(r.headers.get('cache-control')).toBe('no-store');
    const j = await r.json();
    expect(j.ai.configured).toBe(false);
    expect(j.providers[0].configured).toBe(true);
  });

  it('rejects web-page origins', async () => {
    const r = await post('/v1/reputation', { url: 'https://example.com' }, { origin: 'https://evil.example' });
    expect(r.status).toBe(403);
    expect(r.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('answers CORS preflight for extensions', async () => {
    const r = await fetch(`${base}/v1/analyze`, { method: 'OPTIONS', headers: { origin: EXT } });
    expect(r.status).toBe(204);
    expect(r.headers.get('access-control-allow-methods')).toContain('POST');
  });

  it('returns reputation summaries', async () => {
    const r = await post('/v1/reputation', { url: 'https://example.com/a?b=c' });
    expect(r.status).toBe(200);
    expect((await r.json()).status).toBe('checked');
  });

  it.each([
    ['wrong content type', () => post('/v1/reputation', 'url=x', { 'content-type': 'text/plain' }), 415],
    ['invalid JSON', () => post('/v1/reputation', '{nope'), 400],
    ['missing url', () => post('/v1/reputation', {}), 400],
    ['extra fields', () => post('/v1/reputation', { url: 'https://e.com', admin: true }), 400],
    ['oversized url', () => post('/v1/reputation', { url: `https://e.com/${'a'.repeat(5000)}` }), 400],
    ['oversized body', () => post('/v1/analyze', { text: 'a'.repeat(MAX_BODY_BYTES + 10) }), 413],
    ['unknown route', () => post('/v1/admin', {}), 404],
    ['wrong method', () => fetch(`${base}/v1/reputation`, { headers: { origin: EXT } }), 405],
  ])('%s → %i', async (_n, call, status) => {
    const r = await call();
    expect(r.status).toBe(status);
    const j = await r.json();
    expect(j.error).toBeTruthy();
    expect(JSON.stringify(j)).not.toMatch(/stack|at Object\./);
  });

  it('degrades AI analysis explicitly when unconfigured', async () => {
    const r = await post('/v1/analyze', { kind: 'page', text: 'Enter OTP' });
    expect(r.status).toBe(200);
    expect((await r.json()).status).toBe('unavailable');
  });

  it('rate-limits AI endpoints', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) statuses.push((await post('/v1/analyze', { text: 'x' })).status);
    expect(statuses).toContain(429);
  });
});
