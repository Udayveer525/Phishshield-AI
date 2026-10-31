import { describe, expect, it } from 'vitest';
import { assess } from '../src/engine/index.js';
import { editDistance, scriptsIn, skeleton } from '../src/engine/lookalike.js';

const ids = (url: string) => assess(url).signals.filter((s) => s.weight > 0).map((s) => s.id);

describe('lookalike helpers', () => {
  it('maps homoglyphs and digit substitutions to the same skeleton', () => {
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('amaz0n')).toBe(skeleton('amazon'));
    expect(skeleton('pаypal')).toBe(skeleton('paypal')); // Cyrillic а
    expect(skeleton('rnyntra')).toBe(skeleton('myntra'));
    expect(skeleton('onlinesbl')).toBe(skeleton('onlinesbi'));
  });

  it('computes Damerau distance including transpositions', () => {
    expect(editDistance('hdfcbnak', 'hdfcbank')).toBe(1);
    expect(editDistance('flipkart', 'flipkrat')).toBe(1);
    expect(editDistance('abc', 'abcdefgh', 2)).toBe(3);
  });

  it('detects mixed scripts', () => {
    expect(scriptsIn('pаypal').size).toBe(2);
    expect(scriptsIn('paypal').size).toBe(1);
    expect(scriptsIn('भारत').size).toBe(1);
  });
});

describe('deceptive subdomains and brand impersonation', () => {
  it.each([
    ['http://sbi.co.in.secure-login.click/', 'url.embedded_official_domain'],
    ['https://onlinesbi.sbi.kyc-verify.top/', 'url.embedded_official_domain'],
    ['https://paypal.com-account-review.net/', 'url.embedded_official_domain'],
    ['https://hdfcbank-com.verify-user.info/', 'url.embedded_official_domain'],
    ['https://sbi-yono.weebly.com/', 'url.brand_in_subdomain'],
  ])('%s is likely phishing via %s', (url, id) => {
    const a = assess(url);
    expect(ids(url)).toContain(id);
    expect(a.verdict).toBe('likely_phishing');
  });

  it.each([
    'http://sbi-kyc-update.xyz/login.php',
    'https://paytm-kyc.co.in/update',
    'https://incometax-refund.in/claim',
    'https://indiapost-parcel.top/track',
    'https://icici-netbanking-reward.web.app/',
    'https://flipkart-bigbillion-sale.shop/',
  ])('brand + action keyword domain %s is likely phishing', (url) => {
    expect(assess(url).verdict).toBe('likely_phishing');
  });

  it.each([
    ['https://paypa1.com/signin', 'url.char_substitution'],
    ['https://amaz0n-offers.in/claim', 'url.char_substitution'],
    ['https://hdfcbnak.com/', 'url.lookalike_domain'],
    ['https://flipkrat.com/', 'url.lookalike_domain'],
  ])('typosquat %s triggers %s', (url, id) => {
    expect(ids(url)).toContain(id);
    expect(['suspicious', 'likely_phishing']).toContain(assess(url).verdict);
  });

  it('flags IDN homoglyph domains imitating brands', () => {
    const a = assess('https://xn--pypal-4ve.com/');
    expect(a.signals[0]?.id).toBe('url.idn_homoglyph');
    expect(a.verdict).toBe('likely_phishing');
    expect(a.displayHost).toBe('pаypal.com');
  });

  it('flags the @ userinfo trick', () => {
    const a = assess('https://www.google.com@evil-site.ru/');
    expect(ids('https://www.google.com@evil-site.ru/')).toContain('url.userinfo_trick');
    expect(a.verdict).toBe('likely_phishing');
  });

  it('flags IP hosts serving brand login paths', () => {
    const a = assess('http://103.45.67.89/sbi/netbanking/login.html');
    expect(ids('http://103.45.67.89/sbi/netbanking/login.html')).toEqual(expect.arrayContaining(['url.ip_host', 'url.brand_in_path']));
    expect(a.verdict).toBe('likely_phishing');
  });

  it('flags disguised IP notation', () => {
    expect(ids('http://1745240921/login')).toContain('url.ip_obfuscated');
  });

  it('flags tunnels hosting brand pages', () => {
    expect(assess('https://abc123.ngrok-free.app/hdfc/login').verdict).toBe('likely_phishing');
  });
});

describe('encoded and malformed URLs', () => {
  it('flags percent-encoded hostnames', () => {
    expect(ids('https://www.%73%62%69.com/')).toContain('url.encoded_host');
  });

  it('flags double encoding', () => {
    expect(ids('https://example.org/redirect%252F%252Fevil')).toContain('url.double_encoding');
  });

  it('flags embedded redirect targets', () => {
    expect(ids('https://example.org/out?url=https://evil.example/login')).toContain('url.embedded_redirect');
  });

  it('treats javascript: and data: links as suspicious, not inconclusive', () => {
    expect(assess('javascript:alert(document.cookie)').verdict).toBe('suspicious');
    expect(assess('data:text/html;base64,PHNjcmlwdD4=').verdict).toBe('suspicious');
  });

  it('returns inconclusive for unparseable input', () => {
    const a = assess('http://');
    expect(a.verdict).toBe('inconclusive');
    expect(a.limitations.length).toBeGreaterThan(0);
  });

  it('returns inconclusive for an unexpanded shortener', () => {
    const a = assess('https://bit.ly/3AbCdEf');
    expect(a.verdict).toBe('inconclusive');
    expect(a.limitations.join(' ')).toMatch(/destination is unknown/);
  });
});

describe('no single weak indicator causes a warning', () => {
  it.each([
    'http://neverssl.com/',
    'http://old-family-blog.in/2009/03/a-really-long-post-title-about-our-holiday-in-kerala-and-the-backwaters-of-alleppey-with-many-many-words-in-it.html?utm_source=newsletter&utm_medium=email&utm_campaign=2009',
    'https://zzqvtrkm.com/',
    'https://my-site.xyz/',
    'https://login.example.org/',
    'https://my-small-business.myshopify.com/',
  ])('%s is not flagged', (url) => {
    const a = assess(url);
    expect(a.verdict).toBe('no_known_threats');
    expect(a.score).toBeLessThan(30);
  });

  it('HTTP alone carries zero effective weight', () => {
    const a = assess('http://example.com/');
    expect(a.score).toBe(0);
    expect(a.signals.find((s) => s.id === 'url.no_https')?.weight).toBe(0);
  });
});

describe('punycode hyphens', () => {
  it('does not count the xn-- prefix as suspicious hyphens', () => {
    expect(ids('https://xn--pypal-4ve.com/')).not.toContain('url.many_hyphens');
    expect(ids('https://xn--pypal-4ve.com/')).toContain('url.idn_homoglyph');
  });
});
