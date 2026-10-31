/**
 * Frequently impersonated organisations (India-focused plus common global targets).
 *
 * `tokens`       - labels matched exactly against hostname tokens (split on "." and "-").
 * `fuzzyTokens`  - distinctive tokens (>= 5 chars) also matched as substrings and for lookalikes.
 * `domains`      - official registrable domains. A match suppresses impersonation signals; it is
 *                  never treated as proof that a page is safe.
 * `brandSuffixes`- brand-owned TLDs (e.g. `.sbi`), any domain under them is official.
 * `names`        - how the organisation is named in page text (for content/brand-mismatch checks).
 */
export interface Brand {
  id: string;
  name: string;
  category: 'bank' | 'payments' | 'government' | 'ecommerce' | 'telecom' | 'delivery' | 'tech' | 'social' | 'travel';
  tokens: string[];
  fuzzyTokens: string[];
  domains: string[];
  brandSuffixes?: string[];
  names: string[];
}

export const BRANDS: Brand[] = [
  // ---- Indian banks ----
  {
    id: 'sbi',
    name: 'State Bank of India',
    category: 'bank',
    tokens: ['sbi', 'onlinesbi', 'yonosbi', 'sbionline'],
    fuzzyTokens: ['onlinesbi', 'yonosbi'],
    domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'sbi.bank.in', 'sbicard.com', 'sbilife.co.in', 'sbimf.com', 'sbisecurities.in', 'sbigeneral.in'],
    brandSuffixes: ['sbi'],
    names: ['state bank of india', 'sbi', 'yono sbi', 'onlinesbi', 'एसबीआई', 'स्टेट बैंक'],
  },
  {
    id: 'hdfc',
    name: 'HDFC Bank',
    category: 'bank',
    tokens: ['hdfc', 'hdfcbank'],
    fuzzyTokens: ['hdfcbank'],
    domains: ['hdfcbank.com', 'hdfc.bank.in', 'hdfc.com', 'hdfclife.com', 'hdfcergo.com', 'hdfcsec.com', 'hdfcfund.com', 'hdfcbank.net'],
    names: ['hdfc bank', 'hdfc netbanking', 'एचडीएफसी'],
  },
  {
    id: 'icici',
    name: 'ICICI Bank',
    category: 'bank',
    tokens: ['icici', 'icicibank'],
    fuzzyTokens: ['icicibank', 'icici'],
    domains: ['icicibank.com', 'icici.bank.in', 'icicidirect.com', 'icicilombard.com', 'iciciprulife.com', 'icicibank.co.in'],
    names: ['icici bank', 'icici', 'आईसीआईसीआई'],
  },
  {
    id: 'axis',
    name: 'Axis Bank',
    category: 'bank',
    tokens: ['axisbank'],
    fuzzyTokens: ['axisbank'],
    domains: ['axisbank.com', 'axis.bank.in', 'axisbank.co.in', 'axisdirect.in'],
    names: ['axis bank'],
  },
  {
    id: 'kotak',
    name: 'Kotak Mahindra Bank',
    category: 'bank',
    tokens: ['kotak', 'kotakbank'],
    fuzzyTokens: ['kotak'],
    domains: ['kotak.com', 'kotak.bank.in', 'kotaksecurities.com', 'kotaklife.com'],
    names: ['kotak mahindra', 'kotak bank'],
  },
  {
    id: 'pnb',
    name: 'Punjab National Bank',
    category: 'bank',
    tokens: ['pnb', 'pnbindia', 'pnbnet'],
    fuzzyTokens: ['pnbindia'],
    domains: ['pnbindia.in', 'pnb.bank.in', 'netpnb.com', 'pnbnet.org.in'],
    names: ['punjab national bank'],
  },
  {
    id: 'bob',
    name: 'Bank of Baroda',
    category: 'bank',
    tokens: ['bankofbaroda', 'bobibanking', 'bobworld'],
    fuzzyTokens: ['bankofbaroda', 'bobibanking'],
    domains: ['bankofbaroda.in', 'bankofbaroda.com', 'bobibanking.com', 'bankofbaroda.bank.in'],
    names: ['bank of baroda'],
  },
  {
    id: 'canara',
    name: 'Canara Bank',
    category: 'bank',
    tokens: ['canarabank'],
    fuzzyTokens: ['canarabank'],
    domains: ['canarabank.com', 'canarabank.in', 'canarabank.bank.in'],
    names: ['canara bank'],
  },
  // ---- Payments / UPI ----
  {
    id: 'paytm',
    name: 'Paytm',
    category: 'payments',
    tokens: ['paytm'],
    fuzzyTokens: ['paytm'],
    domains: ['paytm.com', 'paytm.in', 'paytmbank.com', 'paytmmoney.com', 'paytmmall.com', 'paytm.me'],
    names: ['paytm', 'पेटीएम'],
  },
  {
    id: 'phonepe',
    name: 'PhonePe',
    category: 'payments',
    tokens: ['phonepe'],
    fuzzyTokens: ['phonepe'],
    domains: ['phonepe.com'],
    names: ['phonepe', 'फोनपे'],
  },
  {
    id: 'npci',
    name: 'NPCI / BHIM UPI',
    category: 'payments',
    tokens: ['npci', 'bhimupi', 'bhim'],
    fuzzyTokens: ['bhimupi'],
    domains: ['npci.org.in', 'bhimupi.org.in'],
    names: ['npci', 'bhim upi', 'national payments corporation'],
  },
  {
    id: 'paypal',
    name: 'PayPal',
    category: 'payments',
    tokens: ['paypal'],
    fuzzyTokens: ['paypal'],
    domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com'],
    names: ['paypal'],
  },
  // ---- Government ----
  {
    id: 'uidai',
    name: 'UIDAI (Aadhaar)',
    category: 'government',
    tokens: ['uidai', 'aadhaar', 'aadhar', 'myaadhaar'],
    fuzzyTokens: ['uidai', 'aadhaar', 'myaadhaar'],
    domains: ['uidai.gov.in'],
    names: ['uidai', 'unique identification authority', 'आधार'],
  },
  {
    id: 'incometax',
    name: 'Income Tax Department',
    category: 'government',
    tokens: ['incometax', 'incometaxindia', 'incometaxrefund'],
    fuzzyTokens: ['incometax'],
    domains: ['incometax.gov.in', 'incometaxindia.gov.in'],
    names: ['income tax department', 'income tax refund', 'आयकर विभाग'],
  },
  {
    id: 'epfo',
    name: 'EPFO',
    category: 'government',
    tokens: ['epfo', 'epfindia'],
    fuzzyTokens: ['epfindia'],
    domains: ['epfindia.gov.in'],
    names: ['epfo', "employees' provident fund", 'employees provident fund'],
  },
  {
    id: 'indiapost',
    name: 'India Post',
    category: 'delivery',
    tokens: ['indiapost', 'indiapostgov'],
    fuzzyTokens: ['indiapost'],
    domains: ['indiapost.gov.in'],
    names: ['india post', 'इंडिया पोस्ट', 'भारतीय डाक'],
  },
  {
    id: 'irctc',
    name: 'IRCTC',
    category: 'travel',
    tokens: ['irctc'],
    fuzzyTokens: ['irctc'],
    domains: ['irctc.co.in', 'irctc.com', 'irctctourism.com', 'irctcipay.com'],
    names: ['irctc', 'indian railway catering'],
  },
  // ---- E-commerce ----
  {
    id: 'amazon',
    name: 'Amazon',
    category: 'ecommerce',
    tokens: ['amazon', 'amzn'],
    fuzzyTokens: ['amazon'],
    domains: ['amazon.in', 'amazon.com', 'amazon.co.uk', 'amazonpay.in', 'amazon.de', 'amazonaws.com', 'amzn.to', 'amzn.in', 'media-amazon.com', 'amazon.jobs'],
    brandSuffixes: ['amazon'],
    names: ['amazon', 'amazon pay'],
  },
  {
    id: 'flipkart',
    name: 'Flipkart',
    category: 'ecommerce',
    tokens: ['flipkart'],
    fuzzyTokens: ['flipkart'],
    domains: ['flipkart.com', 'flipkart.net', 'fkrt.it', 'flixcart.com'],
    names: ['flipkart', 'फ्लिपकार्ट'],
  },
  {
    id: 'myntra',
    name: 'Myntra',
    category: 'ecommerce',
    tokens: ['myntra'],
    fuzzyTokens: ['myntra'],
    domains: ['myntra.com'],
    names: ['myntra'],
  },
  // ---- Telecom ----
  {
    id: 'airtel',
    name: 'Airtel',
    category: 'telecom',
    tokens: ['airtel'],
    fuzzyTokens: ['airtel'],
    domains: ['airtel.in', 'airtel.com'],
    names: ['airtel', 'एयरटेल'],
  },
  {
    id: 'jio',
    name: 'Jio',
    category: 'telecom',
    tokens: ['jio', 'myjio', 'reliancejio'],
    fuzzyTokens: ['reliancejio'],
    domains: ['jio.com', 'jiomart.com', 'ril.com'],
    names: ['reliance jio', 'jio'],
  },
  // ---- Delivery ----
  {
    id: 'dhl',
    name: 'DHL',
    category: 'delivery',
    tokens: ['dhl'],
    fuzzyTokens: [],
    domains: ['dhl.com', 'dhl.co.in', 'dhl.de'],
    names: ['dhl express'],
  },
  {
    id: 'fedex',
    name: 'FedEx',
    category: 'delivery',
    tokens: ['fedex'],
    fuzzyTokens: ['fedex'],
    domains: ['fedex.com'],
    names: ['fedex'],
  },
  {
    id: 'bluedart',
    name: 'Blue Dart',
    category: 'delivery',
    tokens: ['bluedart'],
    fuzzyTokens: ['bluedart'],
    domains: ['bluedart.com'],
    names: ['blue dart', 'bluedart'],
  },
  {
    id: 'delhivery',
    name: 'Delhivery',
    category: 'delivery',
    tokens: ['delhivery'],
    fuzzyTokens: ['delhivery'],
    domains: ['delhivery.com'],
    names: ['delhivery'],
  },
  // ---- Tech / social ----
  {
    id: 'google',
    name: 'Google',
    category: 'tech',
    tokens: ['google', 'gmail', 'googlepay', 'gpay'],
    fuzzyTokens: ['google', 'googlepay'],
    domains: ['google.com', 'google.co.in', 'gmail.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com', 'g.co', 'goo.gl', 'googleapis.com', 'withgoogle.com', 'google.dev', 'blogger.com'],
    brandSuffixes: ['google'],
    names: ['google', 'gmail', 'google pay'],
  },
  {
    id: 'microsoft',
    name: 'Microsoft',
    category: 'tech',
    tokens: ['microsoft', 'office365', 'microsoftonline', 'outlook', 'onedrive'],
    fuzzyTokens: ['microsoft', 'office365', 'microsoftonline'],
    domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com', 'office365.com', 'windows.net', 'bing.com', 'msn.com', 'azure.com', 'microsoft365.com', 'onedrive.com', 'sharepoint.com'],
    brandSuffixes: ['microsoft'],
    names: ['microsoft', 'office 365', 'microsoft 365', 'outlook'],
  },
  {
    id: 'apple',
    name: 'Apple',
    category: 'tech',
    tokens: ['apple', 'appleid', 'icloud', 'itunes'],
    fuzzyTokens: ['appleid', 'icloud'],
    domains: ['apple.com', 'icloud.com', 'apple.co', 'me.com', 'itunes.com'],
    brandSuffixes: ['apple'],
    names: ['apple id', 'icloud'],
  },
  {
    id: 'netflix',
    name: 'Netflix',
    category: 'tech',
    tokens: ['netflix'],
    fuzzyTokens: ['netflix'],
    domains: ['netflix.com', 'nflxext.com', 'nflximg.net'],
    names: ['netflix'],
  },
  {
    id: 'meta',
    name: 'Meta (Facebook / Instagram / WhatsApp)',
    category: 'social',
    tokens: ['facebook', 'instagram', 'whatsapp', 'fb', 'meta'],
    fuzzyTokens: ['facebook', 'instagram', 'whatsapp'],
    domains: ['facebook.com', 'fb.com', 'fb.me', 'messenger.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'wa.me', 'fbcdn.net', 'cdninstagram.com'],
    names: ['facebook', 'instagram', 'whatsapp'],
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    category: 'social',
    tokens: ['linkedin'],
    fuzzyTokens: ['linkedin'],
    domains: ['linkedin.com', 'lnkd.in', 'licdn.com'],
    names: ['linkedin'],
  },
];

const BRAND_BY_ID = new Map(BRANDS.map((b) => [b.id, b]));
export function getBrand(id: string): Brand | undefined {
  return BRAND_BY_ID.get(id);
}

/** True when the registrable domain / suffix is an official domain for this brand. */
export function isOfficialFor(brand: Brand, registrableDomain: string | null, publicSuffix: string | null): boolean {
  if (registrableDomain && brand.domains.includes(registrableDomain)) return true;
  if (publicSuffix && brand.brandSuffixes?.includes(publicSuffix)) return true;
  // RBI-restricted bank.in: `<brandtoken>.bank.in` is reserved for that bank.
  if (brand.category === 'bank' && registrableDomain?.endsWith('.bank.in')) {
    const label = registrableDomain.slice(0, -'.bank.in'.length);
    return brand.tokens.includes(label) || brand.fuzzyTokens.some((t) => label.includes(t));
  }
  return false;
}

/** Any brand that owns this registrable domain. */
export function officialBrandFor(registrableDomain: string | null, publicSuffix: string | null): Brand | undefined {
  return BRANDS.find((b) => isOfficialFor(b, registrableDomain, publicSuffix));
}

/** Restricted registries where impersonation of the same category is implausible. */
export function isRestrictedRegistryFor(category: Brand['category'], registrableDomain: string | null): boolean {
  if (!registrableDomain) return false;
  if (category === 'government' || category === 'delivery') {
    return registrableDomain.endsWith('.gov.in') || registrableDomain.endsWith('.nic.in');
  }
  return false;
}
