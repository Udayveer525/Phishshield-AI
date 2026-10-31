import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { assessDownload, classifyExtension } from '../src/engine/download.js';

const ids = (r: { signals: Array<{ id: string; weight: number }> }) => r.signals.filter((s) => s.weight > 0).map((s) => s.id);

describe('Download Guard', () => {
  it('pauses lure-named APKs from websites', () => {
    const a = assessDownload({ filename: 'C:\\Users\\me\\Downloads\\RTO_E-Challan_2026.apk', url: 'https://cdn.example-files.com/a.apk', referrer: 'https://web.whatsapp.com/' });
    expect(a.filename).toBe('RTO_E-Challan_2026.apk');
    expect(a.fileClass).toBe('android_app');
    expect(ids(a)).toEqual(expect.arrayContaining(['download.apk', 'download.apk_lure']));
    expect(a.verdict).toBe('likely_phishing');
    expect(a.intervene).toBe(true);
  });

  it('catches programs disguised as documents and APKs hidden by MIME', () => {
    expect(assessDownload({ filename: 'Invoice.pdf.exe', url: 'https://x.com/f' }).intervene).toBe(true);
    const apk = assessDownload({ filename: 'wedding-card.pdf', url: 'https://x.com/f', mime: 'application/vnd.android.package-archive' });
    expect(apk.fileClass).toBe('android_app');
    expect(ids(apk)).toContain('download.mime_mismatch');
    expect(apk.intervene).toBe(true);
  });

  it('flags runnable files assembled in the page (HTML smuggling)', () => {
    const a = assessDownload({ filename: 'statement.zip.lnk', url: 'blob:https://evil.example/4f1c', referrer: 'https://evil.example/' });
    expect(ids(a)).toEqual(expect.arrayContaining(['download.built_in_page', 'download.shortcut', 'file.double_extension']));
    expect(a.intervene).toBe(true);
  });

  it('uses the URL engine on the source and the page it came from', () => {
    const a = assessDownload({ filename: 'setup.exe', url: 'http://sbi-kyc-update.xyz/files/setup.exe' });
    expect(ids(a).some((i) => i.startsWith('download.source_'))).toBe(true);
    expect(a.intervene).toBe(true);
  });

  it('repeats Chrome Safe Browsing danger verdicts', () => {
    const a = assessDownload({ filename: 'tool.exe', url: 'https://example.com/tool.exe', danger: 'content' });
    expect(ids(a)).toContain('download.chrome_content');
    expect(a.signals.find((s) => s.id === 'download.chrome_content')!.category).toBe('threat_intel');
  });

  it('lets ordinary downloads through untouched', () => {
    for (const [filename, url] of [
      ['Bank_Statement_Oct.pdf', 'https://www.onlinesbi.sbi/statement'],
      ['photo.jpg', 'https://images.example.com/p.jpg'],
      ['VLC-3.0.21-win64.exe', 'https://get.videolan.org/vlc/3.0.21/win64/vlc-3.0.21-win64.exe'],
      ['report.zip', 'https://drive.example.com/r.zip'],
    ]) {
      const a = assessDownload({ filename: filename!, url: url! });
      expect(a.intervene, filename).toBe(false);
    }
  });

  it('mutes file-type warnings for trusted sources but keeps Chrome threat verdicts', () => {
    const a = assessDownload({ filename: 'company-tool.ps1', url: 'https://intranet.mycorp.com/t.ps1' }, { trustedDomains: ['mycorp.com'] });
    expect(a.intervene).toBe(false);
    const b = assessDownload({ filename: 'x.exe', url: 'https://intranet.mycorp.com/x.exe', danger: 'url' }, { trustedDomains: ['mycorp.com'] });
    expect(b.signals.find((s) => s.id === 'download.chrome_url')!.weight).toBeGreaterThan(0);
  });

  it('classifies extensions', () => {
    expect(classifyExtension('apk')).toBe('android_app');
    expect(classifyExtension('bat')).toBe('script');
    expect(classifyExtension('xlsm')).toBe('macro_document');
    expect(classifyExtension('iso')).toBe('disk_image');
    expect(classifyExtension('', 'application/x-msdownload')).toBe('program');
  });
});

interface Rule {
  id: number;
  action: { type: string };
  condition: { requestDomains: string[]; domainType: string; resourceTypes: string[] };
}

describe('network blocking rulesets', () => {
  const manifest = JSON.parse(readFileSync('src/extension/manifest.json', 'utf8'));
  const load = (id: string) => {
    const res = manifest.declarative_net_request.rule_resources.find((r: { id: string }) => r.id === id);
    return { res, rules: JSON.parse(readFileSync(`src/extension/${res.path}`, 'utf8')) as Rule[] };
  };

  it.each(['malvertising', 'ads'])('%s rules are valid, third-party only and never block top-level pages', (id) => {
    const { rules } = load(id);
    const seen = new Set<number>();
    for (const r of rules) {
      expect(seen.has(r.id)).toBe(false);
      seen.add(r.id);
      expect(r.action.type).toBe('block');
      expect(r.condition.domainType).toBe('thirdParty');
      expect(r.condition.resourceTypes).not.toContain('main_frame');
      for (const d of r.condition.requestDomains) expect(d).toMatch(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
    }
  });

  it('ships the scam-ad shield on and general ad blocking off', () => {
    expect(load('malvertising').res.enabled).toBe(true);
    expect(load('ads').res.enabled).toBe(false);
  });

  it('keeps the lists disjoint', () => {
    const a = new Set(load('malvertising').rules.flatMap((r) => r.condition.requestDomains));
    for (const d of load('ads').rules.flatMap((r) => r.condition.requestDomains)) expect(a.has(d)).toBe(false);
  });

  it('covers the native-ad and ad-exchange domains seen on Indian news sites', () => {
    const ads = new Set(load('ads').rules.flatMap((r) => r.condition.requestDomains));
    for (const d of ['doubleclick.net', 'googlesyndication.com', 'amazon-adsystem.com', 'taboola.com', 'tblcontent.com', 'outbrain.com', 'clmbtech.com', 'izooto.com']) expect(ads.has(d), d).toBe(true);
    expect(ads.size).toBeGreaterThanOrEqual(80);
  });

  it('hides only ad-specific containers (no generic class names that break sites or trip ad-block detection)', () => {
    const css = readFileSync('src/extension/content/adhide.css', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    expect(css).toMatch(/display:\s*none !important/);
    for (const generic of [/(^|[\s,])\.ad[\s,{]/, /\.adsbox/, /\[class\*=['"]?ad['"]?\]/]) expect(css).not.toMatch(generic);
  });

  it('requests only the permissions it uses', () => {
    expect(manifest.permissions.sort()).toEqual(['activeTab', 'declarativeNetRequest', 'downloads', 'scripting', 'storage', 'webNavigation']);
    expect(manifest.host_permissions).toBeUndefined();
  });
});
