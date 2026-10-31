import type { Verdict } from '../../shared/types.js';

export type Lang = 'en' | 'hi';

const STRINGS = {
  tab_site: { en: 'This site', hi: 'यह साइट' },
  tab_scan: { en: 'Scan link', hi: 'लिंक जाँचें' },
  tab_message: { en: 'Check message', hi: 'मैसेज जाँचें' },
  tab_tools: { en: 'Tools', hi: 'टूल्स' },
  src_registry: { en: 'Domain age', hi: 'डोमेन की उम्र' },
  scan_qr_screen: { en: 'Scan a QR code on this screen', hi: 'इस स्क्रीन का QR कोड जाँचें' },
  scan_qr_hint: { en: 'Make sure the QR code is fully visible, then click. The screenshot is decoded on your device and discarded.', hi: 'QR कोड पूरी तरह दिखे, फिर क्लिक करें। स्क्रीनशॉट आपके डिवाइस पर ही पढ़ा जाता है।' },
  upi_found: { en: 'UPI payment links in this message', hi: 'इस मैसेज में UPI भुगतान लिंक' },
  risk_score: { en: 'Risk score', hi: 'जोखिम स्कोर' },
  score_note: { en: 'Heuristic score, not a probability', hi: 'अनुमान आधारित स्कोर, संभावना नहीं' },
  why: { en: 'Why PhishShield says this', hi: 'PhishShield ऐसा क्यों कह रहा है' },
  no_findings: { en: 'No warning signs were found in the checks that ran.', hi: 'जो जाँचें हुईं उनमें कोई चेतावनी संकेत नहीं मिला।' },
  what_to_do: { en: 'What to do', hi: 'क्या करें' },
  sources: { en: 'Checks performed', hi: 'की गई जाँचें' },
  src_local: { en: 'Local checks', hi: 'स्थानीय जाँच' },
  src_reputation: { en: 'Reputation lists', hi: 'प्रतिष्ठा सूचियाँ' },
  src_ai: { en: 'AI analysis', hi: 'AI विश्लेषण' },
  local_desc: { en: 'On your device, no data sent', hi: 'आपके डिवाइस पर, कोई डेटा नहीं भेजा गया' },
  ai_label: { en: 'AI findings: model-generated, not independently verified', hi: 'AI निष्कर्ष: मॉडल द्वारा, स्वतंत्र रूप से सत्यापित नहीं' },
  evidence: { en: 'Technical evidence', hi: 'तकनीकी साक्ष्य' },
  limitations: { en: 'Limitations', hi: 'सीमाएँ' },
  analyze_page: { en: 'Analyze page', hi: 'पेज जाँचें' },
  analyze_page_hint: { en: 'Reads visible text on this page, on your device', hi: 'इस पेज का दिखने वाला टेक्स्ट आपके डिवाइस पर पढ़ता है' },
  deep_ai: { en: 'Deep AI analysis', hi: 'गहन AI विश्लेषण' },
  deep_ai_hint: { en: 'Sends a redacted excerpt to your PhishShield server', hi: 'छिपाई गई जानकारी के साथ अंश आपके PhishShield सर्वर पर भेजता है' },
  listen: { en: 'Listen', hi: 'सुनें' },
  rescan: { en: 'Re-check', hi: 'फिर जाँचें' },
  trust_site: { en: 'I trust this site', hi: 'मुझे इस साइट पर भरोसा है' },
  untrust_site: { en: 'Stop trusting this site', hi: 'भरोसा हटाएँ' },
  scan_placeholder: { en: 'Paste a link, e.g. sbi-kyc-update.in/login', hi: 'लिंक पेस्ट करें, जैसे sbi-kyc-update.in/login' },
  scan: { en: 'Scan', hi: 'जाँचें' },
  scan_note: { en: 'The link is checked without opening it.', hi: 'लिंक को खोले बिना जाँचा जाता है।' },
  message_placeholder: { en: 'Paste an SMS, WhatsApp or e-mail you received…', hi: 'मिला हुआ SMS, WhatsApp या ई-मेल यहाँ पेस्ट करें…' },
  check_message: { en: 'Check message', hi: 'मैसेज जाँचें' },
  explain_ai: { en: 'Explain with AI', hi: 'AI से समझें' },
  links_found: { en: 'Links in this message', hi: 'इस मैसेज के लिंक' },
  no_links: { en: 'No links found in the message.', hi: 'मैसेज में कोई लिंक नहीं मिला।' },
  message_tactics: { en: 'Scam tactics in the text', hi: 'टेक्स्ट में धोखाधड़ी की तरकीबें' },
  loading: { en: 'Checking…', hi: 'जाँच हो रही है…' },
  not_web: { en: 'PhishShield checks websites (http/https). This page is a browser or extension page.', hi: 'PhishShield वेबसाइटें (http/https) जाँचता है। यह ब्राउज़र या एक्सटेंशन का पेज है।' },
  report: { en: 'Report fraud: cybercrime.gov.in · 1930', hi: 'धोखाधड़ी की रिपोर्ट: cybercrime.gov.in · 1930' },
  consent_title: { en: 'Send for AI analysis?', hi: 'AI विश्लेषण के लिए भेजें?' },
  consent_body: {
    en: 'PhishShield will send this page’s address (without query string), title, form-field counts and up to 8,000 characters of visible text to your PhishShield server, which forwards it to {provider}. E-mails, phone, card, Aadhaar and PAN numbers are redacted first. Passwords and anything you typed are never collected. PhishShield stores nothing.',
    hi: 'PhishShield इस पेज का पता (क्वेरी के बिना), शीर्षक, फ़ॉर्म फ़ील्ड की गिनती और दिखने वाले टेक्स्ट के 8,000 अक्षर तक आपके PhishShield सर्वर पर भेजेगा, जो इसे {provider} को भेजता है। ई-मेल, फ़ोन, कार्ड, आधार और PAN नंबर पहले छिपा दिए जाते हैं। पासवर्ड या आपके द्वारा टाइप की गई कोई चीज़ कभी नहीं ली जाती। PhishShield कुछ भी सेव नहीं करता।',
  },
  ai_provider_generic: { en: 'the AI provider configured on that server', hi: 'उस सर्वर पर सेट किए गए AI प्रदाता' },
  consent_remember: { en: 'Don’t ask again', hi: 'फिर से न पूछें' },
  send: { en: 'Send', hi: 'भेजें' },
  cancel: { en: 'Cancel', hi: 'रद्द करें' },
  api_offline: { en: 'Local-only mode: the PhishShield server is not reachable. Local checks still work.', hi: 'केवल स्थानीय मोड: PhishShield सर्वर से संपर्क नहीं हो पा रहा। स्थानीय जाँच काम कर रही है।' },
  page_protected: { en: 'This page can’t be inspected (browser-protected page or still loading).', hi: 'यह पेज जाँचा नहीं जा सकता (ब्राउज़र-सुरक्षित पेज या अभी लोड हो रहा है)।' },
} as const;

export type StringKey = keyof typeof STRINGS;

export function t(key: StringKey, lang: Lang): string {
  return STRINGS[key][lang];
}

export const VERDICT_LABEL: Record<Verdict, Record<Lang, string>> = {
  no_known_threats: { en: 'No known threats', hi: 'कोई ज्ञात खतरा नहीं' },
  suspicious: { en: 'Suspicious', hi: 'संदिग्ध' },
  likely_phishing: { en: 'Likely phishing', hi: 'संभावित फ़िशिंग' },
  confirmed_malicious: { en: 'Known dangerous site', hi: 'ज्ञात खतरनाक साइट' },
  inconclusive: { en: 'Couldn’t fully check', hi: 'पूरी जाँच नहीं हो सकी' },
};

export const VERDICT_ACTION_HI: Record<Verdict, string> = {
  confirmed_malicious:
    'यह साइट तुरंत छोड़ें। पासवर्ड, OTP, कार्ड या UPI जानकारी न डालें। अगर डाल दी है तो तुरंत अपने बैंक से संपर्क करें और cybercrime.gov.in पर रिपोर्ट करें या 1930 पर कॉल करें।',
  likely_phishing: 'यहाँ लॉगिन या भुगतान न करें। लिंक के बजाय संस्था का आधिकारिक ऐप खोलें या पता खुद टाइप करें।',
  suspicious: 'सावधान रहें। कोई भी निजी या भुगतान जानकारी डालने से पहले वेबसाइट का पता जाँचें।',
  no_known_threats: 'कोई ज्ञात खतरा नहीं मिला, लेकिन यह सुरक्षा की गारंटी नहीं है। OTP, पासवर्ड या भुगतान की अनपेक्षित माँग से सावधान रहें।',
  inconclusive: 'PhishShield इस लिंक की पूरी जाँच नहीं कर सका। सावधानी रखें और जानकारी डालने से पहले पता जाँचें।',
};

export const VERDICT_ICON: Record<Verdict, string> = {
  no_known_threats: 'shield-dot',
  suspicious: 'shield-alert',
  likely_phishing: 'shield-alert',
  confirmed_malicious: 'shield-x',
  inconclusive: 'shield-q',
};
