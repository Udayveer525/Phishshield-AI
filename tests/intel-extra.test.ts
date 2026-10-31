import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { assess } from '../src/engine/index.js';
import { createAiService } from '../src/server/ai/service.js';
import { createApp } from '../src/server/app.js';
import { HIBP_BREACHES_URL, createBreachCatalog, indexBreaches } from '../src/server/intel/hibp.js';
import { IANA_RDAP_BOOTSTRAP, createRdapClient, isSafeBase, parseBootstrap, parseRdapDomain } from '../src/server/intel/rdap.js';
import { createIntelService } from '../src/server/intel/service.js';
import { VT_API, createVirusTotalProvider, vtUrlId } from '../src/server/intel/virustotal.js';
import type { FetchLike } from '../src/server/util.js';

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

const HASH = 'a'.repeat(64);
const vtReport = (malicious: number, extra: Record<string, unknown> = {}) => ({
  data: {
    id: HASH,
    type: 'file',
    attributes: {
      last_analysis_stats: { malicious, suspicious: 1, harmless: 0, undetected: 60 - malicious, timeout: 2, 'type-unsupported': 5, failure: 0 },
      last_analysis_date: 1_760_000_000,
      first_submission_date: 1_750_000_000,
      meaningful_name: 'SBI_KYC.apk',
      type_description: 'Android',
      times_submitted: 12,
      total_votes: { harmless: 0, malicious: 4 },
      popular_threat_classification: { suggested_threat_label: 'trojan.banker/smsspy' },
      ...extra,
    },
  },
});

describe('VirusTotal (lookup only)', () => {
  it('uses the documented URL identifier', () => {
    expect(vtUrlId('http://www.example.com/')).toBe('aHR0cDovL3d3dy5leGFtcGxlLmNvbS8');
  });

  it('looks up files by hash with the API key header, never uploads', async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => json(vtReport(40)));
    const vt = createVirusTotalProvider({ apiKey: 'vt-key', fetchImpl });
    const { finding, file } = await vt.lookupFile(HASH.toUpperCase());
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`${VT_API}/files/${HASH}`);
    expect(init?.method ?? 'GET').toBe('GET');
    expect((init?.headers as Record<string, string>)['x-apikey']).toBe('vt-key');
    expect(finding).toMatchObject({ status: 'match', threatTypes: ['trojan.banker/smsspy'], detections: { malicious: 40, suspicious: 1, total: 61 } });
    expect(file).toMatchObject({ meaningfulName: 'SBI_KYC.apk', timesSubmitted: 12, permalink: `https://www.virustotal.com/gui/file/${HASH}` });
    // Cached: no second network call.
    await vt.lookupFile(HASH);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('needs at least 3 engines to confirm', async () => {
    const vt = createVirusTotalProvider({ apiKey: 'k', fetchImpl: async () => json(vtReport(2)) });
    const { finding } = await vt.lookupFile(HASH);
    expect(finding.status).toBe('no_match');
    expect(finding.detections?.malicious).toBe(2);
  });

  it('maps "not found", auth and quota errors honestly', async () => {
    const notFound = createVirusTotalProvider({ apiKey: 'k', fetchImpl: async () => json({ error: { code: 'NotFoundError', message: 'x' } }, 404) });
    expect((await notFound.lookupFile(HASH)).finding).toMatchObject({ status: 'no_match', message: expect.stringMatching(/never seen/) });
    const auth = createVirusTotalProvider({ apiKey: 'k', fetchImpl: async () => json({ error: { code: 'WrongCredentialsError' } }, 401) });
    expect((await auth.check('https://e.com/')).message).toMatch(/rejected the server API key/);
    const quota = createVirusTotalProvider({ apiKey: 'k', fetchImpl: async () => json({ error: { code: 'QuotaExceededError' } }, 429) });
    expect((await quota.check('https://e.com/')).status).toBe('error');
  });

  it('enforces the free-tier rate limit locally', async () => {
    let t = 0;
    const fetchImpl = vi.fn<FetchLike>(async () => json({}, 404));
    const vt = createVirusTotalProvider({ apiKey: 'k', fetchImpl, now: () => t, perMinute: 2 });
    await vt.check('https://a.com/');
    await vt.check('https://b.com/');
    const third = await vt.check('https://c.com/');
    expect(third.message).toMatch(/4 lookups\/minute/);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    t += 61_000;
    expect((await vt.check('https://d.com/')).status).toBe('no_match');
  });

  it('is explicit when unconfigured and rejects bad hashes', async () => {
    const vt = createVirusTotalProvider({});
    expect((await vt.check('https://e.com/')).status).toBe('unconfigured');
    expect((await createVirusTotalProvider({ apiKey: 'k' }).lookupFile('nope')).finding.status).toBe('error');
  });
});

describe('HIBP breach catalogue', () => {
  const catalogue = [
    { Name: 'Dominos', Title: "Domino's India", Domain: 'dominos.co.in', BreachDate: '2021-04-01', PwnCount: 22_527_655, DataClasses: ['Email addresses', 'Names', 'Phone numbers'], IsVerified: true },
    { Name: 'Old', Title: 'Old', Domain: 'dominos.co.in', BreachDate: '2015-01-01', PwnCount: 10, DataClasses: [], IsVerified: false },
    { Name: 'Fake', Title: 'Fake', Domain: 'fabricated.com', BreachDate: '2020-01-01', PwnCount: 1, DataClasses: [], IsVerified: false, IsFabricated: true },
    { Name: 'Spam', Title: 'Spam', Domain: 'spamlist.com', BreachDate: '2020-01-01', PwnCount: 1, DataClasses: [], IsVerified: true, IsSpamList: true },
    { Name: 'NoDomain', Title: 'x', Domain: '', BreachDate: '2020-01-01', PwnCount: 1, DataClasses: [], IsVerified: true },
    { garbage: true },
  ];

  it('indexes by domain, newest first, skipping fabricated and spam lists', () => {
    const idx = indexBreaches(catalogue);
    expect(idx.get('dominos.co.in')!.map((b) => b.name)).toEqual(['Dominos', 'Old']);
    expect(idx.has('fabricated.com')).toBe(false);
    expect(idx.has('spamlist.com')).toBe(false);
    expect(idx.size).toBe(1);
  });

  it('downloads with a User-Agent and matches locally', async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => json(catalogue));
    const cat = createBreachCatalog({ enabled: true, userAgent: 'PhishShield-test', fetchImpl });
    expect(cat.lookup('dominos.co.in')).toBeUndefined(); // not loaded yet: unknown, not "no breaches"
    await cat.refresh();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(HIBP_BREACHES_URL);
    expect((init?.headers as Record<string, string>)['user-agent']).toBe('PhishShield-test');
    expect(cat.lookup('DOMINOS.co.in')![0]!.pwnCount).toBe(22_527_655);
    expect(cat.lookup('example.com')).toEqual([]);
    expect(cat.describe()).toMatchObject({ entries: 2, license: expect.stringMatching(/CC BY 4\.0/) });
  });

  it('keeps the previous catalogue when a refresh fails', async () => {
    let fail = false;
    const cat = createBreachCatalog({ enabled: true, userAgent: 'x', fetchImpl: async () => (fail ? json({}, 503) : json(catalogue)) });
    await cat.refresh();
    fail = true;
    await cat.refresh();
    expect(cat.lookup('dominos.co.in')!.length).toBe(2);
    expect(cat.describe().lastError).toBe('HTTP 503');
  });
});

describe('RDAP domain age', () => {
  const bootstrap = {
    version: '1.0',
    services: [
      [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
      [['in'], ['http://insecure.example/', 'https://rdap.nixiregistry.in/rdap/']],
      [['evil'], ['https://127.0.0.1/rdap/', 'http://10.0.0.1/']],
    ],
  };
  const domainObj = {
    objectClassName: 'domain',
    ldhName: 'EXAMPLE.COM',
    events: [
      { eventAction: 'registration', eventDate: '2026-10-28T10:00:00Z' },
      { eventAction: 'expiration', eventDate: '2027-10-28T10:00:00Z' },
    ],
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar LLC']]] }],
  };

  it('keeps only https, public registry endpoints from the bootstrap', () => {
    const map = parseBootstrap(bootstrap);
    expect(map.get('com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(map.get('in')).toBe('https://rdap.nixiregistry.in/rdap/');
    expect(map.has('evil')).toBe(false);
    expect(isSafeBase('https://localhost/')).toBe(false);
    expect(isSafeBase('https://user:pw@rdap.example.com/')).toBe(false);
  });

  it('parses registration, expiry and registrar', () => {
    const info = parseRdapDomain(domainObj, 'example.com', 1);
    expect(info).toMatchObject({ status: 'found', registeredAt: Date.parse('2026-10-28T10:00:00Z'), registrar: 'Example Registrar LLC' });
  });

  it('queries the right registry with the ICANN registrable domain', async () => {
    const fetchImpl = vi.fn<FetchLike>(async (url) => (url === IANA_RDAP_BOOTSTRAP ? json(bootstrap) : json(domainObj)));
    const rdap = createRdapClient({ enabled: true, fetchImpl });
    const info = await rdap.lookup('login.secure.example.com');
    expect(fetchImpl.mock.calls[1]![0]).toBe('https://rdap.verisign.com/com/v1/domain/example.com');
    expect(info?.status).toBe('found');
    await rdap.lookup('www.example.com');
    expect(fetchImpl).toHaveBeenCalledTimes(2); // bootstrap + one domain query; second is cached
  });

  it('reports unsupported TLDs, unknown domains and unsafe redirects without guessing', async () => {
    const fetchImpl = vi.fn<FetchLike>(async (url) => {
      if (url === IANA_RDAP_BOOTSTRAP) return json(bootstrap);
      if (url.includes('/domain/missing.com')) return json({ errorCode: 404 }, 404);
      return new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data' } });
    });
    const rdap = createRdapClient({ enabled: true, fetchImpl });
    expect((await rdap.lookup('shop.io'))?.status).toBe('unsupported');
    expect((await rdap.lookup('missing.com'))?.status).toBe('not_found');
    expect((await rdap.lookup('redirect.com'))?.status).toBe('error');
    expect(fetchImpl.mock.calls.some(([u]) => u.includes('169.254'))).toBe(false);
  });

  it('does nothing when disabled', async () => {
    const fetchImpl = vi.fn<FetchLike>();
    expect(await createRdapClient({ enabled: false, fetchImpl }).lookup('example.com')).toBeUndefined();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('intel service enrichment', () => {
  const fakeVt = { id: 'virustotal', name: 'VirusTotal', onDemand: true as const, isConfigured: () => true, describe: () => ({}), check: vi.fn(async () => ({ providerId: 'virustotal', providerName: 'VirusTotal', status: 'no_match' as const, checkedAt: 1, detections: { malicious: 1, suspicious: 0, harmless: 70, undetected: 20, total: 91 } })) };
  const list = { id: 'list', name: 'List', isConfigured: () => true, describe: () => ({}), check: async () => ({ providerId: 'list', providerName: 'List', status: 'no_match' as const, checkedAt: 1 }) };

  it('runs on-demand providers only for deep checks', async () => {
    const svc = createIntelService([list, fakeVt]);
    const shallow = await svc.check('https://example.com/');
    expect(shallow.status).toBe('checked');
    expect(shallow.findings.find((f) => f.providerId === 'virustotal')?.status).toBe('skipped');
    expect(fakeVt.check).not.toHaveBeenCalled();
    const deep = await svc.check('https://example.com/', { deep: true });
    expect(fakeVt.check).toHaveBeenCalledOnce();
    // A single engine flag becomes evidence, never confirmation.
    const a = assess('https://example.com/', { reputation: deep });
    expect(a.verdict).not.toBe('confirmed_malicious');
    expect(a.signals.some((s) => s.id === 'intel.virustotal.minority')).toBe(true);
  });

  it('adds domain age and breaches, capped by a deadline', async () => {
    const rdap = { id: 'rdap' as const, name: 'RDAP', isConfigured: () => true, describe: () => ({}), lookup: () => new Promise<never>(() => undefined) };
    const breaches = { id: 'hibp_breaches' as const, name: 'HIBP', isConfigured: () => true, describe: () => ({}), refresh: async () => undefined, start: () => () => undefined, lookup: (d: string) => (d === 'dominos.co.in' ? [{ name: 'D', title: 'D', domain: d, breachDate: '2021-04-01', pwnCount: 1, dataClasses: [], isVerified: true }] : []) };
    const svc = createIntelService([list], { rdap, breaches, domainDeadlineMs: 20 });
    const r = await svc.check('https://www.dominos.co.in/menu');
    expect(r.breaches?.[0]?.domain).toBe('dominos.co.in');
    expect(r.domain).toMatchObject({ status: 'timeout', domain: 'dominos.co.in' });
    expect(svc.providers().map((p) => p.id)).toEqual(['list', 'rdap', 'hibp_breaches']);
  });

  it('never enriches private hosts', async () => {
    const rdap = { id: 'rdap' as const, name: 'RDAP', isConfigured: () => true, describe: () => ({}), lookup: vi.fn() };
    const r = await createIntelService([list], { rdap }).check('http://192.168.1.1/admin');
    expect(r.status).toBe('skipped');
    expect(rdap.lookup).not.toHaveBeenCalled();
  });
});

describe('POST /v1/file', () => {
  async function withApp(files: Parameters<typeof createApp>[0]['files'], fn: (post: (b: unknown) => Promise<Response>) => Promise<void>) {
    const app = createApp({ intel: createIntelService([]), ai: createAiService(null), files, allowedOrigins: [], version: 't' });
    const server = createServer((req, res) => void app(req, res));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      await fn((b) => fetch(`${base}/v1/file`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) }));
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  it('accepts only a SHA-256 and returns the finding without cache hints', async () => {
    const lookupFile = vi.fn(async () => ({ finding: { providerId: 'virustotal', providerName: 'VirusTotal', status: 'no_match' as const, checkedAt: 1, cacheTtlSec: 900 } }));
    await withApp({ configured: true, lookupFile }, async (post) => {
      const ok = await post({ sha256: HASH.toUpperCase() });
      const j = await ok.json();
      expect(j.finding.status).toBe('no_match');
      expect(j.finding.cacheTtlSec).toBeUndefined();
      expect(lookupFile).toHaveBeenCalledWith(HASH);
      expect((await post({ sha256: 'abc' })).status).toBe(400);
      expect((await post({ sha256: HASH, content: 'TVqQ' })).status).toBe(400);
    });
  });

  it('degrades explicitly when file reputation is not configured', async () => {
    await withApp(undefined, async (post) => {
      expect((await (await post({ sha256: HASH })).json()).finding.status).toBe('unconfigured');
    });
  });
});
