import { describe, expect, it } from 'vitest';
import { assess } from '../src/engine/index.js';

/**
 * False-positive guard: real banking, payment, government, delivery and ordinary business URLs
 * must never produce a warning from local heuristics.
 */
const LEGIT = {
  banking: [
    'https://retail.onlinesbi.sbi/retail/login.htm',
    'https://www.onlinesbi.sbi/',
    'https://sbi.co.in/web/personal-banking/accounts/kyc',
    'https://www.sbicard.com/en/personal/credit-cards.page',
    'https://netbanking.hdfcbank.com/netbanking/',
    'https://www.hdfcbank.com/personal/pay/cards/credit-cards',
    'https://www.hdfc.bank.in/',
    'https://infinity.icicibank.com/corp/AuthenticationController',
    'https://www.icicidirect.com/',
    'https://omni.axisbank.co.in/axisretailbanking/',
    'https://www.axisbank.com/retail/cards',
    'https://netbanking.kotak.com/knb2/',
    'https://www.pnbindia.in/',
    'https://www.bankofbaroda.in/personal-banking',
    'https://canarabank.com/',
    'https://sbi.bank.in/',
  ],
  payments: [
    'https://paytm.com/recharge',
    'https://www.phonepe.com/business-solutions/',
    'https://pay.google.com/about/',
    'https://www.npci.org.in/what-we-do/upi/product-overview',
    'https://www.bhimupi.org.in/',
    'https://www.paypal.com/signin',
    'https://razorpay.com/payment-links/',
    'https://rzp.io/l/abc123',
    'https://www.payu.in/',
    'https://www.billdesk.com/',
    'https://cred.club/',
    'https://www.amazon.in/amazonpay/home',
  ],
  government: [
    'https://www.incometax.gov.in/iec/foportal/',
    'https://eportal.incometax.gov.in/iec/foservices/#/login',
    'https://myaadhaar.uidai.gov.in/',
    'https://uidai.gov.in/en/my-aadhaar/update-aadhaar.html',
    'https://unifiedportal-mem.epfindia.gov.in/memberinterface/',
    'https://services.gst.gov.in/services/login',
    'https://www.cybercrime.gov.in/',
    'https://sancharsaathi.gov.in/sfc/',
    'https://www.irctc.co.in/nget/train-search',
    'https://parivahan.gov.in/parivahan/',
  ],
  delivery: [
    'https://www.indiapost.gov.in/_layouts/15/dop.portal.tracking/trackconsignment.aspx',
    'https://www.bluedart.com/tracking',
    'https://www.delhivery.com/track/package/1234567890',
    'https://www.dhl.com/in-en/home/tracking.html',
    'https://www.fedex.com/en-in/tracking.html',
    'https://www.shiprocket.in/shipment-tracking/',
  ],
  business: [
    'https://www.amazon.in/gp/cart/view.html',
    'https://www.flipkart.com/account/login',
    'https://www.myntra.com/login',
    'https://www.swiggy.com/',
    'https://www.zomato.com/bangalore',
    'https://www.airtel.in/myaccount/',
    'https://www.jio.com/selfcare/login/',
    'https://www.netflix.com/in/login',
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'https://accounts.google.com/signin/v2/identifier',
    'https://appleid.apple.com/sign-in',
    'https://www.linkedin.com/login',
    'https://web.whatsapp.com/',
    'https://github.com/login',
    'https://docs.google.com/forms/d/e/abc/viewform',
    'https://my-bakery-shop.in/menu',
    'https://www.tatamotors.com/',
    'https://www.zerodha.com/',
    'https://kite.zerodha.com/',
    'https://www.makemytrip.com/flights/',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://www.thehindu.com/news/national/sbi-warns-customers-about-kyc-fraud/article123.ece',
    'https://www.paypal.com.au/',
    'https://www.kodak.com/',
    'https://www.amazon.jobs/en/',
  ],
};

describe('legitimate URLs are not flagged', () => {
  for (const [group, urls] of Object.entries(LEGIT)) {
    describe(group, () => {
      it.each(urls)('%s', (url) => {
        const a = assess(url);
        expect(a.verdict, a.signals.map((s) => `${s.id}:${s.weight}`).join(' ')).toBe('no_known_threats');
        expect(a.score).toBeLessThan(30);
      });
    });
  }

  it('official domains carry an informational note, never a claim of safety', () => {
    const a = assess('https://www.onlinesbi.sbi/');
    const note = a.signals.find((s) => s.id === 'url.official_domain');
    expect(note?.weight).toBe(0);
    expect(note?.detail).toMatch(/does not prove/);
    expect(a.limitations.join(' ')).toMatch(/not proof of safety/);
  });
});
