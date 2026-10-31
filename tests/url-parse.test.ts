import { describe, expect, it } from 'vitest';
import { isPrivateOrLocalHost, lookupUrl, parseUrl, type ParsedUrl } from '../src/engine/url.js';

function ok(input: string, opts?: { allowSchemeless?: boolean }): ParsedUrl {
  const r = parseUrl(input, opts);
  if (!r.ok) throw new Error(`expected ${input} to parse: ${r.message}`);
  return r;
}

describe('parseUrl - normalisation', () => {
  it('lowercases the host, strips the fragment and default port', () => {
    const p = ok('HTTPS://WWW.Example.COM:443/Path?q=1#frag');
    expect(p.host).toBe('www.example.com');
    expect(p.href).toBe('https://www.example.com/Path?q=1');
    expect(p.port).toBe('');
    expect(p.registrableDomain).toBe('example.com');
    expect(p.subdomain).toBe('www');
  });

  it('resolves multi-part public suffixes', () => {
    const p = ok('https://netbanking.sbi.co.in/login');
    expect(p.registrableDomain).toBe('sbi.co.in');
    expect(p.domainLabel).toBe('sbi');
    expect(p.publicSuffix).toBe('co.in');
  });

  it('treats the RBI-restricted bank.in zone as a public suffix', () => {
    const p = ok('https://www.hdfc.bank.in/');
    expect(p.registrableDomain).toBe('hdfc.bank.in');
    expect(p.publicSuffix).toBe('bank.in');
    expect(p.subdomain).toBe('www');
  });

  it('strips a trailing FQDN dot', () => {
    expect(ok('https://sbi.co.in./').host).toBe('sbi.co.in');
  });

  it('removes control and zero-width characters before parsing', () => {
    expect(ok('https://exa​mple.com/\u0000').host).toBe('example.com');
  });

  it('accepts schemeless input only when allowed (manual scanner)', () => {
    expect(parseUrl('example.com/login').ok).toBe(false);
    const p = ok('example.com/login', { allowSchemeless: true });
    expect(p.assumedScheme).toBe(true);
    expect(p.scheme).toBe('http');
    expect(ok('example.com:8443/x', { allowSchemeless: true }).port).toBe('8443');
  });

  it('builds lookup URLs without query or fragment by default (privacy)', () => {
    const p = ok('https://shop.example.com/a/b?token=SECRET#x');
    expect(lookupUrl(p)).toBe('https://shop.example.com/a/b');
    expect(lookupUrl(p, true)).toBe('https://shop.example.com/a/b?token=SECRET');
  });
});

describe('parseUrl - malformed and hostile input', () => {
  it.each([
    ['', 'empty'],
    ['   ', 'empty'],
    ['http://', 'invalid'],
    ['https://exa mple.com', 'invalid'],
    ['not a url at all', 'invalid'],
  ])('rejects %j as %s', (input, reason) => {
    const r = parseUrl(input);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe(reason);
  });

  it('rejects oversized URLs', () => {
    const r = parseUrl(`https://example.com/${'a'.repeat(9000)}`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('too_long');
  });

  it.each(['javascript:alert(1)', 'data:text/html;base64,PGgxPg==', 'file:///etc/passwd', 'ftp://example.com', 'chrome://settings'])(
    'reports unsupported scheme for %s',
    (input) => {
      const r = parseUrl(input);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toBe('unsupported_scheme');
    },
  );

  it('never throws on random junk', () => {
    const junk = ['http://[::1', 'https://%', 'http://a..b', 'https://xn--/', 'http://@', 'https://:80', '\u0000\u0001', 'http://￿.com'];
    for (const j of junk) expect(() => parseUrl(j)).not.toThrow();
  });
});

describe('parseUrl - hosts', () => {
  it('detects IPv4 hosts', () => {
    const p = ok('http://103.45.67.89/login');
    expect(p.isIp).toBe(true);
    expect(p.ipVersion).toBe(4);
    expect(p.registrableDomain).toBeNull();
    expect(p.ipObfuscated).toBe(false);
  });

  it('detects integer / hex IP obfuscation', () => {
    const p = ok('http://1745240921/'); // 104.6.x.x in integer form
    expect(p.isIp).toBe(true);
    expect(p.ipObfuscated).toBe(true);
    const h = ok('http://0x68.0x2a.0x10.0x01/');
    expect(h.host).toBe('104.42.16.1');
    expect(h.ipObfuscated).toBe(true);
  });

  it('detects IPv6 hosts', () => {
    const p = ok('http://[2001:db8::1]/');
    expect(p.ipVersion).toBe(6);
    expect(p.host).toBe('2001:db8::1');
    expect(lookupUrl(p)).toBe('http://[2001:db8::1]/');
  });

  it('decodes punycode for display', () => {
    const p = ok('https://xn--pypal-4ve.com/');
    expect(p.usesPunycode).toBe(true);
    expect(p.unicodeHost).toBe('pаypal.com'); // Cyrillic "а"
  });

  it('converts Unicode input to punycode', () => {
    const p = ok('https://аpple.com/');
    expect(p.host.startsWith('xn--')).toBe(true);
  });

  it('captures userinfo used for the @ trick', () => {
    const p = ok('https://www.sbi.co.in@evil.example/');
    expect(p.hasUserInfo).toBe(true);
    expect(p.userInfo).toBe('www.sbi.co.in');
    expect(p.host).toBe('evil.example');
  });

  it('flags private, local and metadata addresses', () => {
    for (const h of ['localhost', 'api.localhost', '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', 'router.lan', 'printer.local', 'intranet', '::1', 'fd12:3456::1', 'fe80::1', '::ffff:10.0.0.1']) {
      expect(isPrivateOrLocalHost(h), h).toBe(true);
    }
    for (const h of ['8.8.8.8', '103.45.67.89', 'example.com', '172.32.0.1', '2001:4860::8888']) {
      expect(isPrivateOrLocalHost(h), h).toBe(false);
    }
    expect(ok('http://2130706433/').isPrivateOrLocal).toBe(true); // 127.0.0.1 in integer form
  });
});
