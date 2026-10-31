import { describe, expect, it, vi } from 'vitest';
import { assess } from '../src/engine/index.js';
import { createOpenPhishProvider, matchFeed, parseFeed } from '../src/server/intel/openphish.js';
import { GSB_ENDPOINT, createSafeBrowsingProvider, parseDuration } from '../src/server/intel/safe-browsing.js';
import { createIntelService } from '../src/server/intel/service.js';
import type { IntelProvider } from '../src/server/intel/types.js';
import type { FetchLike } from '../src/server/util.js';

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('Google Safe Browsing adapter', () => {
  it('reports unconfigured without calling the network', async () => {
    const fetchImpl = vi.fn<FetchLike>();
    const p = createSafeBrowsingProvider({ fetchImpl });
    expect(p.isConfigured()).toBe(false);
    expect((await p.check('https://example.com/')).status).toBe('unconfigured');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('sends the documented request shape and maps matches', async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      json({ matches: [{ threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'https://evil.example/' }, cacheDuration: '300.000s' }] }),
    );
    const p = createSafeBrowsingProvider({ apiKey: 'k', fetchImpl });
    const r = await p.check('https://evil.example/');
    expect(r.status).toBe('match');
    expect(r.threatTypes).toEqual(['SOCIAL_ENGINEERING']);
    expect(r.cacheTtlSec).toBe(300);
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url.startsWith(`${GSB_ENDPOINT}?key=`)).toBe(true);
    const body = JSON.parse(String(init?.body));
    expect(body.threatInfo.threatEntries).toEqual([{ url: 'https://evil.example/' }]);
    expect(body.threatInfo.threatTypes).toContain('SOCIAL_ENGINEERING');
  });

  it('maps an empty object to no_match', async () => {
    const p = createSafeBrowsingProvider({ apiKey: 'k', fetchImpl: async () => json({}) });
    expect((await p.check('https://example.com/')).status).toBe('no_match');
  });

  it('reports timeouts as timeout, never as a result', async () => {
    const fetchImpl: FetchLike = (_u, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('t'), { name: 'TimeoutError' })));
      });
    const p = createSafeBrowsingProvider({ apiKey: 'k', fetchImpl, timeoutMs: 20 });
    const r = await p.check('https://example.com/');
    expect(r.status).toBe('timeout');
    expect(r.threatTypes).toBeUndefined();
  });

  it.each([
    ['HTTP 500', async () => new Response('oops', { status: 500 })],
    ['HTTP 429', async () => new Response('quota', { status: 429 })],
    ['HTTP 403', async () => new Response('bad key', { status: 403 })],
    ['malformed JSON', async () => new Response('{not json', { status: 200 })],
    ['wrong shape', async () => json({ matches: [{ nope: true }] })],
    ['network error', async () => {
      throw new TypeError('fetch failed');
    }],
  ] as Array<[string, FetchLike]>)('%s → error status', async (_name, fetchImpl) => {
    const p = createSafeBrowsingProvider({ apiKey: 'k', fetchImpl });
    const r = await p.check('https://example.com/');
    expect(r.status).toBe('error');
    expect(r.message).toBeTruthy();
  });

  it('parses protobuf durations defensively', () => {
    expect(parseDuration('300s')).toBe(300);
    expect(parseDuration('12.5s')).toBe(13);
    expect(parseDuration('999999999s')).toBe(86400);
    expect(parseDuration('5m')).toBeUndefined();
  });
});

const FEED = ['https://evil-kyc.example/sbi/login.php', 'http://phish.example.net/kit/', 'https://sites.google.com/view/fake-hdfc', '# comment', 'not a url', ''].join('\n');

describe('OpenPhish feed matching', () => {
  const index = parseFeed(FEED);

  it('parses only valid URLs', () => {
    expect(index.count).toBe(3);
  });

  it('matches exact URLs ignoring query, fragment and trailing slash', () => {
    expect(matchFeed(index, 'https://evil-kyc.example/sbi/login.php?session=1#x')).toBe('exact_url');
    expect(matchFeed(index, 'http://phish.example.net/kit')).toBe('exact_url');
  });

  it('matches pages under a listed kit directory', () => {
    expect(matchFeed(index, 'http://phish.example.net/kit/step2/otp.html')).toBe('url_prefix');
  });

  it('matches other paths on a dedicated phishing host only as "host"', () => {
    expect(matchFeed(index, 'https://evil-kyc.example/other')).toBe('host');
  });

  it('never extends a listing to a shared platform host', () => {
    expect(matchFeed(index, 'https://sites.google.com/view/my-real-school')).toBeNull();
  });

  it('host-only matches are strong evidence, not confirmation', () => {
    const a = assess('https://evil-kyc.example/other', {
      reputation: { status: 'checked', findings: [{ providerId: 'openphish', providerName: 'OpenPhish', status: 'match', matchType: 'host', checkedAt: 1 }] },
    });
    expect(a.verdict).not.toBe('confirmed_malicious');
    expect(a.signals.some((s) => s.id === 'intel.openphish.host')).toBe(true);
  });
});

describe('OpenPhish provider lifecycle', () => {
  const textResponse = (body: string, url = 'https://openphish.com/feed.txt', type = 'text/plain') => {
    const r = new Response(body, { status: 200, headers: { 'content-type': type } });
    Object.defineProperty(r, 'url', { value: url });
    return r;
  };

  it('rejects non-allow-listed feed URLs at construction', () => {
    expect(() => createOpenPhishProvider({ enabled: true, feedUrl: 'http://169.254.169.254/latest/meta-data' })).toThrow();
  });

  it('errors before the feed is loaded instead of reporting clean', async () => {
    const p = createOpenPhishProvider({ enabled: true, fetchImpl: async () => new Response('x', { status: 503 }) });
    await p.refresh();
    const r = await p.check('https://evil-kyc.example/sbi/login.php');
    expect(r.status).toBe('error');
    expect(r.message).toMatch(/HTTP 503/);
  });

  it('loads the feed and reports dataset freshness', async () => {
    let t = 1_000_000;
    const p = createOpenPhishProvider({ enabled: true, fetchImpl: async () => textResponse(FEED), now: () => t });
    await p.refresh();
    const r = await p.check('https://evil-kyc.example/sbi/login.php');
    expect(r.status).toBe('match');
    expect(r.datasetUpdatedAt).toBe(1_000_000);
    t += 40 * 3600_000;
    expect((await p.check('https://example.com/')).message).toMatch(/older than 36 hours/);
  });

  it('refuses redirects to other hosts and wrong content types', async () => {
    const redirected = createOpenPhishProvider({ enabled: true, fetchImpl: async () => textResponse(FEED, 'https://attacker.example/feed.txt') });
    await redirected.refresh();
    expect((await redirected.check('https://evil-kyc.example/sbi/login.php')).status).toBe('error');
    const html = createOpenPhishProvider({ enabled: true, fetchImpl: async () => textResponse(FEED, undefined, 'text/html') });
    await html.refresh();
    expect((await html.check('https://evil-kyc.example/sbi/login.php')).status).toBe('error');
  });

  it('aborts oversized feeds', async () => {
    const big = 'https://a.example/x\n'.repeat(600_000); // ~12 MB
    const p = createOpenPhishProvider({ enabled: true, fetchImpl: async () => textResponse(big) });
    await p.refresh();
    expect(p.describe().lastError).toBe('feed too large');
  });
});

function fakeProvider(over: Partial<IntelProvider> & { result?: Awaited<ReturnType<IntelProvider['check']>> }): IntelProvider & { calls: string[] } {
  const calls: string[] = [];
  return {
    id: over.id ?? 'fake',
    name: over.name ?? 'Fake',
    isConfigured: over.isConfigured ?? (() => true),
    describe: () => ({}),
    calls,
    check:
      over.check ??
      (async (url) => {
        calls.push(url);
        return over.result ?? { providerId: 'fake', providerName: 'Fake', status: 'no_match', checkedAt: 1, cacheTtlSec: 60 };
      }),
  };
}

describe('intel service', () => {
  it('never forwards private or local addresses', async () => {
    const p = fakeProvider({});
    const svc = createIntelService([p]);
    for (const u of ['http://localhost:3000/', 'http://192.168.1.1/', 'http://169.254.169.254/latest/meta-data', 'http://[::1]/']) {
      expect((await svc.check(u)).status).toBe('skipped');
    }
    expect(p.calls).toEqual([]);
  });

  it('strips query strings and fragments before lookup', async () => {
    const p = fakeProvider({});
    await createIntelService([p]).check('https://shop.example.com/pay?token=SECRET#frag');
    expect(p.calls).toEqual(['https://shop.example.com/pay']);
  });

  it('caches definitive answers and not failures', async () => {
    const ok = fakeProvider({});
    const svc = createIntelService([ok]);
    await svc.check('https://example.com/');
    const second = await svc.check('https://example.com/');
    expect(ok.calls.length).toBe(1);
    expect(second.findings[0]?.fromCache).toBe(true);

    let n = 0;
    const failing = fakeProvider({ check: async () => ({ providerId: 'f', providerName: 'F', status: 'error', checkedAt: n++ }) });
    const svc2 = createIntelService([failing]);
    await svc2.check('https://example.com/');
    await svc2.check('https://example.com/');
    expect(n).toBe(2);
  });

  it('reports partial and unavailable states, and survives throwing providers', async () => {
    const good = fakeProvider({ id: 'a' });
    const bad = fakeProvider({
      id: 'b',
      check: async () => {
        throw new Error('boom');
      },
    });
    expect((await createIntelService([good, bad]).check('https://example.com/')).status).toBe('partial');
    expect((await createIntelService([bad]).check('https://example.com/')).status).toBe('unavailable');
  });

  it('reports not_configured when nothing is set up, listing each provider', async () => {
    const r = await createIntelService([fakeProvider({ isConfigured: () => false })]).check('https://example.com/');
    expect(r.status).toBe('not_configured');
    expect(r.findings[0]?.status).toBe('unconfigured');
  });

  it('does not leak internal cache hints', async () => {
    const r = await createIntelService([fakeProvider({})]).check('https://example.com/');
    expect(r.findings[0]).not.toHaveProperty('cacheTtlSec');
  });
});
