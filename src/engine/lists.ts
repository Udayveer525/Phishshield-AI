/** Static lists used by the local URL rules. Kept separate so they are easy to review and extend. */

export const URL_SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'cutt.ly', 'rb.gy', 'shorturl.at',
  'tiny.cc', 'ow.ly', 'buff.ly', 'rebrand.ly', 's.id', 't.ly', 'bit.do', 'shorte.st', 'adf.ly', 'tiny.one',
  'short.gy', 'surl.li', 'urlz.fr', 'qr.ae', 'lnkd.in', 'amzn.to', 'fkrt.it', 'wa.link', 'linktr.ee', 'shrtco.de',
  'u.to', 'clck.ru', 'gg.gg', 'bl.ink', 'snip.ly', 'tinu.be', '2u.pw', 'urlr.me',
]);

/** First-party shorteners owned by brands: still hide the destination, but not abusive by themselves. */
export const BRAND_SHORTENERS = new Set(['lnkd.in', 'amzn.to', 'fkrt.it', 'g.co', 'goo.gl', 'wa.me', 'fb.me', 'paytm.me', 'amzn.in']);

/** TLDs disproportionately used for abuse in public reporting. Weak signal only, never alone. */
export const ABUSED_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'icu', 'cyou', 'rest', 'click', 'country', 'kim',
  'work', 'support', 'buzz', 'monster', 'sbs', 'cfd', 'bond', 'beauty', 'hair', 'quest', 'lol', 'mom', 'autos',
  'boats', 'homes', 'yachts', 'motorcycles', 'skin', 'makeup', 'shop', 'live', 'online', 'site', 'website',
  'space', 'fun', 'store', 'pw', 'cc', 'su', 'vip', 'win', 'loan', 'bid', 'date', 'review', 'party', 'trade',
  'stream', 'gdn', 'men', 'link', 'help', 'cam',
]);

/** Free hosting / site builders: anyone can publish here, so brand names on them deserve scrutiny. */
export const FREE_HOSTING_SUFFIXES = [
  '000webhostapp.com', 'weebly.com', 'wixsite.com', 'wix.com', 'firebaseapp.com', 'web.app', 'pages.dev',
  'workers.dev', 'vercel.app', 'netlify.app', 'github.io', 'gitlab.io', 'glitch.me', 'repl.co', 'replit.app',
  'herokuapp.com', 'onrender.com', 'blogspot.com', 'wordpress.com', 'sites.google.com', 'webflow.io',
  'square.site', 'godaddysites.com', 'mystrikingly.com', 'yolasite.com', 'jimdosite.com', 'framer.website',
  'surge.sh', 'azurewebsites.net', 'web.core.windows.net', 'r2.dev', 'ipfs.io', 'dweb.link', 'fleek.co',
  'myshopify.com', 'carrd.co', 'notion.site', 'typedream.app', 'edgeone.app', 'translate.goog',
];

/** Tunnelling services expose a developer's machine publicly; rarely used by legitimate consumer sites. */
export const TUNNEL_SUFFIXES = [
  'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'localtunnel.me',
  'pinggy.link', 'devtunnels.ms', 'localhost.run', 'lhr.life',
];

export const DYNAMIC_DNS_SUFFIXES = [
  'duckdns.org', 'ddns.net', 'hopto.org', 'zapto.org', 'no-ip.org', 'no-ip.biz', 'sytes.net', 'servebeer.com',
  'dynu.net', 'mooo.com', 'freedns.org', 'dyndns.org', 'myftp.biz', 'redirectme.net', 'ddnsfree.com',
];

/** Words common in credential-harvesting and KYC-scam URLs. Contextual only. */
export const SENSITIVE_URL_WORDS = [
  'login', 'log-in', 'signin', 'sign-in', 'logon', 'verify', 'verification', 'validate', 'kyc', 'ekyc', 'rekyc',
  'update', 'secure', 'security', 'account', 'acc', 'banking', 'netbanking', 'ibanking', 'wallet', 'otp',
  'reward', 'rewards', 'refund', 'unlock', 'unblock', 'suspend', 'suspended', 'blocked', 'confirm', 'password',
  'passwd', 'credential', 'claim', 'prize', 'lottery', 'gift', 'bonus', 'cashback', 'kbc', 'pan', 'pancard',
  'aadhaar', 'aadhar', 'support', 'helpdesk', 'customercare', 'care', 'alert', 'auth', 'recover', 'recovery',
  'reactivate', 'activation', 'billing', 'invoice', 'payment', 'pay', 'redeem', 'points', 'yono', 'mpin',
  'upi', 'card', 'creditcard', 'limit', 'loan', 'challan', 'parcel', 'delivery', 'tracking', 'customs',
  'offer', 'offers', 'sale', 'free', 'win', 'winner', 'lucky', 'giveaway', 'kyc-update', 'netbank',
];

/** Query parameters that commonly carry a redirect destination. */
export const REDIRECT_PARAMS = ['url', 'redirect', 'redirect_uri', 'redirect_url', 'next', 'goto', 'target', 'dest', 'destination', 'continue', 'return', 'returnurl', 'return_to', 'u', 'link', 'out', 'r', 'to'];

export function hostMatchesSuffix(host: string, suffixes: Iterable<string>): string | undefined {
  for (const s of suffixes) {
    if (host === s || host.endsWith(`.${s}`)) return s;
  }
  return undefined;
}
