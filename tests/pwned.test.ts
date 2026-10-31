import { describe, expect, it, vi } from 'vitest';
import { PWNED_RANGE_URL, checkPwnedPassword, countForSuffix, sha1Hex } from '../src/shared/pwned.js';

describe('Pwned Passwords k-anonymity', () => {
  it('hashes with SHA-1 (upper-case hex)', async () => {
    expect(await sha1Hex('password')).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  });

  it('parses range responses and ignores padding rows', () => {
    const body = '003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0';
    expect(countForSuffix(body, '1e4c9b93f3f0682250b6cf8331b7ee68fd8')).toBe(9_659_365);
    expect(countForSuffix(body, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')).toBe(0);
    expect(countForSuffix(body, 'ABC')).toBe(0);
  });

  it('sends only the 5-character prefix, with padding, and no credentials', async () => {
    const fetchImpl = vi.fn(async () => new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\n'));
    const r = await checkPwnedPassword('password', fetchImpl as unknown as typeof fetch);
    expect(r).toEqual({ ok: true, count: 42, prefix: '5BAA6' });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${PWNED_RANGE_URL}5BAA6`);
    expect((init.headers as Record<string, string>)['Add-Padding']).toBe('true');
    expect(init.credentials).toBe('omit');
    expect(JSON.stringify(init)).not.toMatch(/1E4C9B93/);
  });

  it('retries without the padding header if the first request fails, and reports errors', async () => {
    let n = 0;
    const flaky = vi.fn(async () => {
      if (n++ === 0) throw new TypeError('CORS');
      return new Response('');
    });
    expect(await checkPwnedPassword('x', flaky as unknown as typeof fetch)).toMatchObject({ ok: true, count: 0 });
    expect(await checkPwnedPassword('x', (async () => new Response('', { status: 503 })) as unknown as typeof fetch)).toMatchObject({ ok: false });
    expect(await checkPwnedPassword('')).toMatchObject({ ok: false });
  });
});
