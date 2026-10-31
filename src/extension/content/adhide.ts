/**
 * Ad-space collapser (opt-in, runs only when "Block ads and trackers" and "Hide empty ad spaces"
 * are both on). When an ad request is blocked at the network layer the slot never fills, but the
 * site's own wrapper keeps its reserved height and shows as a blank box. adhide.css hides the
 * known slot elements; this script also collapses the dedicated wrapper the slot sat in, but only
 * when that wrapper is clearly an ad container and holds nothing else visible — so real content is
 * never removed. It reads layout only; it never reads page text, forms or what the user types.
 */
(() => {
  // Well-known ad-slot elements. Deliberately specific: generic names like ".ad" are avoided because
  // sites reuse them for real content and as ad-blocker-detection bait.
  const SLOTS = [
    'ins.adsbygoogle',
    "div[id^='div-gpt-ad']",
    "div[id^='google_ads_iframe']",
    "div[id^='taboola-']",
    '.trc_related_container',
    '.OUTBRAIN',
    '.ob-widget',
    "div[id^='mgid_']",
    "div[id^='ezoic-pub-ad']",
    "div[id^='rc-widget-']",
    "ins[id^='aswift']",
    'amp-ad',
    "amp-embed[type='taboola']",
    "amp-embed[type='outbrain']",
  ].join(',');

  // A wrapper is treated as a dedicated ad box only when its id/class names say so as a whole word.
  const AD_WORD = /(^|[-_ ])(ad|ads|advert|advertisement|adslot|ad-slot|adunit|ad-unit|adbox|ad-box|adwrap|ad-wrap|adwrapper|ad-wrapper|adcontainer|ad-container|adspace|ad-space|adholder|ad-holder|sponsored|dfp|gpt)([-_ 0-9]|$)/i;

  const collapsed = new WeakSet<Element>();

  // Short "Advertisement" / "Sponsored" captions that sites print above an ad slot. They are not real
  // content, so a wrapper left with only such a caption is still collapsed.
  const LABEL_TEXT = /^(ad|ads|advt|advert|advertisement|advertisements|sponsored|sponsored content|promoted|ad feedback|werbung|anzeige)$/i;

  function visible(el: Element): boolean {
    const h = (el as HTMLElement).offsetHeight;
    const w = (el as HTMLElement).offsetWidth;
    return h > 2 && w > 2 && getComputedStyle(el).display !== 'none' && getComputedStyle(el).visibility !== 'hidden';
  }

  function isAdCaption(el: Element): boolean {
    return el.childElementCount === 0 && LABEL_TEXT.test((el.textContent ?? '').trim());
  }

  function isRealContent(el: Element, slot: Element): boolean {
    return el !== slot && !collapsed.has(el) && visible(el) && !isAdCaption(el);
  }

  // The slot filled with a real, sized iframe → an ad actually rendered (rare once blocking is on),
  // so leave everything alone.
  function slotIsEmpty(slot: Element): boolean {
    const frame = slot.querySelector('iframe');
    if (frame && visible(frame)) return false;
    return !slot.querySelector('img, video, canvas');
  }

  function hide(el: Element): void {
    if (collapsed.has(el)) return;
    collapsed.add(el);
    (el as HTMLElement).style.setProperty('display', 'none', 'important');
  }

  function collapse(): void {
    for (const slot of Array.from(document.querySelectorAll(SLOTS))) {
      if (!slotIsEmpty(slot)) continue;
      hide(slot);
      // Walk up at most three levels, collapsing each ancestor that is a labelled ad box (or that
      // held only this slot) and has nothing else visible left in it.
      let node: Element | null = slot.parentElement;
      for (let i = 0; i < 3 && node && node !== document.body; i++) {
        const otherVisible = Array.from(node.children).some((c) => isRealContent(c, slot));
        if (otherVisible) break;
        const labelled = AD_WORD.test(`${node.id} ${node.className}`) || node.childElementCount === 1;
        if (!labelled) break;
        const next: Element | null = node.parentElement;
        hide(node);
        node = next;
      }
    }
  }

  const run = () => {
    try {
      collapse();
    } catch {
      /* layout read can throw on detached nodes; ignore */
    }
  };

  run();
  if (document.readyState !== 'complete') window.addEventListener('load', run, { once: true });

  // Ad slots are often injected after load; re-check when the DOM changes, but no more than ~4×/sec.
  let timer = 0;
  const mo = new MutationObserver(() => {
    if (timer) return;
    timer = window.setTimeout(() => {
      timer = 0;
      run();
    }, 250);
  });
  mo.observe(document.documentElement, { childList: true, subtree: true });
  // Stop watching after 15 s: by then slots have settled and we avoid running forever on busy pages.
  window.setTimeout(() => mo.disconnect(), 15000);
})();
