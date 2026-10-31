# Demo script (about 7 minutes)

New to the project? Read [LECTURE.md](LECTURE.md) first. It explains everything from zero.

Everything here uses the harmless sample files in [`demo/`](../demo). The expected results below come from the real engine, and `tests/demo-files.test.ts` checks them on every `npm test`, so the demo can't silently drift.

> **About the sample files.** None of them is malware.
> - The "APK" is a ZIP containing a permission list and no code. It can't be installed.
> - The PDF's JavaScript only shows an alert.
> - The HTML's "smuggled" blob is the text "PhishShield demo".
>
> They exist to trigger PhishShield's *static* checks safely. Antivirus software may still flag them by pattern. If so, demo from the copy on the presenting laptop.

---

## Before you go on stage (5 minutes)

1. **Build:**

   ```bash
   npm run build
   ```

2. **Load the extension.** On `chrome://extensions`, choose **Load unpacked** → `dist/extension`, then pin PhishShield.
3. **Start the server.** Put the keys in `.env`: `GROQ_API_KEY`, and optionally `GSB_API_KEY` and `VT_API_KEY`. Then:

   ```bash
   npm run server
   ```

   Check that the log lists OpenPhish, RDAP, the HIBP breach catalogue and the AI provider.
4. **Test the connection.** In the extension's **Settings**, click **Test**. Every provider should show as configured (or say why not).
5. **Get your QR codes ready.** Open [`demo/qr/upi-refund-scam.png`](../demo/qr/upi-refund-scam.png) in a browser tab, so you can scan it off the screen.
6. **Warm the AI.** Run one Deep AI analysis beforehand to confirm the key works. After that, leave about 30 s between AI calls (Groq's free tier).

---

## The script

### 1. The hook (20 s)

> "Most phishing extensions check a URL against a blocklist. But in India people lose money through **UPI QR codes, fake KYC apps sent on WhatsApp, and scam-ad pop-ups**, and those never touch a blocklist. PhishShield covers those too, explains every verdict, and never uploads your files or your passwords."

### 2. A UPI "refund" QR (60 s). The headline feature.

1. With `demo/qr/upi-refund-scam.png` open, click PhishShield → **Tools** → **Scan a QR code on this screen**.
2. **Expected:** **Likely UPI scam, 60/100.** The big line reads: *"Scanning this QR sends money: ₹4,999 to Refund Desk 9876543210@ybl"*.
   - *Why:* "Says you will receive money, but this QR takes money".
   - *What to do:* report at **1930**.
3. **Say:** "You never need a UPI PIN to receive money. The screenshot is decoded on this laptop and thrown away. Nothing was uploaded."
4. **Contrast.** Open `upi-shop-normal.png` and scan again. **No known threats**: ₹120 to Sharma Kirana, with "check the name your UPI app shows". No false alarm on a normal shop QR.
5. *(Optional.)* Scan `upi-kyc-fee-scam.png`. **Suspicious, 55:** the payee calls itself SBI but uses a personal UPI ID, and asks for a "KYC verification fee".

### 3. A fake KYC app (60 s)

1. In **Tools**, click **Scan a file**. The Security Center opens.
2. Drop in `demo/files/SBI_YONO_KYC_Update.apk`.
3. **Expected:** **Likely dangerous, 97/100.**
   - *App named like a bank app*
   - *App can read incoming SMS, including bank OTPs*
   - *App can read your SMS inbox*
   - plus the accessibility-service permission
4. **Point at "File details → SHA-256":** "Only this fingerprint goes to VirusTotal, never the file. Uploading to VirusTotal would make the file available to its paying customers. We studied that and designed around it." With `VT_API_KEY` set, the VirusTotal row shows the lookup result. For a file VT has never seen, it says so plainly; it doesn't say "clean".

### 4. A phishing attachment (40 s)

1. Drop in `demo/files/Secure_Message_HDFC.html`.
2. **Expected:** **Likely dangerous, 75.** *Attachment is a login page* and *Builds a hidden download (HTML smuggling)*.
   - **Links inside the file:** `hdfc-netbanking-verify.top` is listed with its own verdict.
3. *(Optional.)* `Electricity_Bill_Disconnection.pdf` gives **Suspicious, 45**: *PDF runs JavaScript when opened*, plus the extracted link. `Salary_Revision_2026.docm` gives **Suspicious, 59**: macros.
4. *(Optional.)* `normal_notes.txt` gives **No known threats**.

### 5. Download Guard (40 s)

You need a live download for this. Start the slow demo server, which serves the harmless APK padded to about 3 MB at about 300 KB/s:

```bash
python scripts/demo-download-server.py
```

1. Open `http://127.0.0.1:8098/RTO_E-Challan_2026.apk`.
2. **Expected:** the download **pauses** within the first 100 KB, and the **Download Guard** page opens.
   - *"Download paused · Likely phishing"* and *"Paused at 90 KB of 3.0 MB"*, with the reasons, for example *App named like a traffic challan app*.
   - **Cancel download** is the main button.
   - **Continue** stays disabled until you tick *I understand the risk*.
3. Click **Cancel**. The page shows *"Cancelled. The file was not saved."*
4. **Say:** "It looks only at the name, type and source, and it never opens the file. Ordinary downloads like PDFs, photos and installers from official sites go straight through."

> **Why the slow server?** Chrome can't pause a download whose bytes have all arrived. A 690-byte file over localhost finishes before any extension can pause it; we saw this in real Chrome on 31 Oct 2026. In that case the Download Guard page instead offers **Delete**. Real scam APKs are several MB, so they get paused. In our real-Chrome test the 3 MB download stopped at 90 KB, and Cancel removed the partial file.

### 6. A phishing URL, with registry and breach context (60 s)

1. Visit `http://sbi.co.in.secure-login.click/kyc`. The warning page appears before the page loads (the domain needn't exist).
   - It explains that the address *starts with* `sbi.co.in` but belongs to `secure-login.click`. **Likely phishing, 74.**
2. Point at **Report to Google Safe Browsing** next to Listen: "One click opens Google's report form with this address filled in. Reported sites end up protecting every Chrome user." Don't submit a report for the demo domain.
3. Click **Go back to safety**.
4. Visit `https://dominos.co.in/` and open the popup.
   - **No known threats** (never "safe").
   - **Domain age:** *Registered 2005-03-03 (21 years ago)*.
   - **Breach history:** *Domino's India, 2021-03, 2,25,27,655 accounts: names, phone numbers, addresses*, with HIBP attribution.
5. **Say:** "This isn't a warning; the site is real. It explains why a scam caller might know your address. The breach list is downloaded once a day and matched on our server, so HIBP never learns which sites you visit."
6. **Confirmed threat.** Copy any URL from `https://openphish.com/feed.txt` into **Scan link**. It shows **Confirmed malicious**, attributed to *OpenPhish Community Feed*. Only verified intel can produce "confirmed".

### 7. Ads and scam ads (40 s)

Use an ad-heavy news site you've tried beforehand (we verified on `ndtv.com`).

1. Open the site **with the ad toggle off** first, so judges see the ads.
2. Open **Tools → Shields**. **Scam-ad shield** is on by default. Turn on **Block ads and trackers**.
3. Click **Reload this page to apply**. Rules only affect new requests; ads already on the page stay until reload.
4. Open the popup again. It shows *"N blocked here"* next to each shield.
5. If empty "Advertisement" boxes remain, turn on **Hide empty ad spaces** in Settings (Chrome asks for site access) and reload.

**Say:** "Two toggles, two jobs. The scam-ad shield blocks the pop-under and push networks that deliver fake virus alerts and prize pages, so it's on by default. Mainstream ad and tracker blocking is a privacy and comfort feature, off by default because some sites break. Chrome applies the rules itself; PhishShield never sees your traffic. Ads served by the site itself, like YouTube's, can't be blocked at the network level by any extension of this kind."

### 8. A leaked password (30 s)

1. Go to the Security Center → **Password check** and type `password`.
2. **Expected:** *Found in 5,23,72,427 leaked password lists* (52 million; the number changes as HIBP grows). The page then shows exactly what was sent: *only "5BAA6"*.
3. **Say:** "That's k-anonymity, the technique Have I Been Pwned built with Cloudflare. Five characters of a hash, out of forty. The password never leaves the browser."

### 9. AI explanation (40 s, optional)

On a page with scam text, or with a message in **Check message** such as:

> Dear customer your electricity connection will be disconnected tonight at 9.30 pm because previous month bill was not updated. Contact our officer 9876543210. Pay now: http://bit.ly/3xYzAbc

1. Click **Explain with AI**. The consent dialog says what will be sent and to whom.
2. The answer appears in a separate dashed *"AI · model-generated"* block, in English and Hindi.
3. **Say:** "The AI can explain and raise concern. It can never mark a site safe or confirmed. Its weight is capped, and its quotes are checked against the real text."

### 10. Close (20 s)

> "Five verdicts, never 'safe'. Files, QR codes, downloads, ads, passwords and pages, all checked on your device first. We studied VirusTotal and Have I Been Pwned and kept their best idea: **send the least data that still answers the question.**"

---

## Likely judge questions

| Question | Short answer | Details |
| --- | --- | --- |
| "How accurate is it?" | We don't claim a number, because we haven't measured on a labelled dataset yet. That's on the roadmap. The tests show specific behaviours, including about 70 legitimate Indian sites that must not be flagged. | [FEATURES.md §12](FEATURES.md) |
| "Why not just upload files to VirusTotal?" | Uploads become available to VT's paying customers, and the free API is non-commercial. Hash lookup gives the same answer for known malware and leaks nothing about private files. | [research/VIRUSTOTAL.md §4](research/VIRUSTOTAL.md) |
| "What do you send to your server?" | The URL without its query string; the registrable domain for RDAP; a SHA-256 for files; redacted text for AI only after consent. Passwords never go to our server: only 5 hash characters go directly to HIBP. | [README privacy notice](../README.md#privacy-notice) |
| "Isn't this just an ad blocker plus a blocklist?" | Both are small parts. The core is the on-device engine: URL deception rules, UPI analysis, file inspection, Hindi scam language and explainable verdicts. Blocklists are one layer of five. | [FEATURES.md §1](FEATURES.md) |
| "What if the AI is tricked by the page?" | It can only add capped weight, its quotes must appear verbatim in the page, and it can never lower or confirm a verdict. | [HOW-IT-WORKS.md §4.1](HOW-IT-WORKS.md) |
| "Why does it need 'Read your browsing history'?" | That is Chrome's wording for `webNavigation`, which is needed to check each page as it loads. We keep no history: per-tab results live in memory only. | [FEATURES.md §11](FEATURES.md) |
