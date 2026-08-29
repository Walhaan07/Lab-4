# Site Safety Checker — browser extension (Lab 4, Demo 4)

A browser extension that **embeds a button on every page the browser visits**. The button
displays `You are on "URL"`, and pressing it runs **49 tests** on the current site to decide
whether it is spam / phishing and to give it a **safety rating (A–F, 0–100)**.

| Requirement | Where it is implemented |
|---|---|
| **Part 1** — embed a button on all visited pages showing `You are on "URL"` | `extension/js/content.js` + `extension/manifest.json` |
| **Part 2** — pressing the button tests the site for spam and rates it | `extension/js/spam-analyzer.js` (49 tests), rendered by `content.js` |

---

## 1. Loading it in Microsoft Edge

1. Open **`edge://extensions`**.
2. Turn on **Developer mode** (bottom left).
3. Click **Load unpacked**.
4. Select the **`extension`** folder — the one containing `manifest.json`. Do not select the
   folder above it, and do not select the manifest file itself.
5. Visit any website. The button appears in the bottom right corner; press it to run the scan.

### To use it on the sample pages (or any page opened from disk)

Pages opened from disk have a `file:///C:/...` address, and **browsers do not run extensions on
those unless you allow it**, one extension at a time:

1. On `edge://extensions`, click **Details** on *Site Safety Checker*.
2. Switch on **Allow access to file URLs**.
3. Reload the page you are testing.

Without that switch the button will not appear on `test-pages/safe-sample.html`, and the page
will look completely untouched. Nothing is wrong with the extension — the browser simply never
ran it. Pages served over `http://` or `https://` (including `http://localhost`) need no switch.

Chrome is identical (`chrome://extensions`), because Edge and Chrome use the same engine.
For **Firefox**, rename `manifest.firefox.json` to `manifest.json`, then load it from
`about:debugging#/runtime/this-firefox` → *Load Temporary Add-on…*

After editing any file, press **Reload** on the extension card, then refresh the page you are
testing.

> Browsers also block extensions on their own internal pages (`edge://`, `chrome://`, the
> add-on store), so the button will not appear there either. That is a browser rule, not a
> fault in the extension.

---

## 2. What is in the folder

```
extension/                  <-- load THIS folder as an unpacked extension
├── manifest.json           Manifest V3 (Edge / Chrome)
├── manifest.firefox.json   Manifest V3 variant for Firefox
├── popup.html              toolbar popup
├── css/popup.css           styles for the popup only
├── icons/                  icon16 / icon48 / icon128 .png
└── js/
    ├── spam-analyzer.js    THE ENGINE - all 49 tests and the scoring
    ├── content.js          PART 1 + PART 2 - injected into every page
    ├── panel-style.js      the button / report CSS, injected as text
    ├── background.js       service worker: toolbar badge, per-tab results
    └── popup.js            toolbar popup logic

test-pages/                 four self-contained pages, one per rating band
├── safe-sample.html        clean page          - rates A (100)
├── caution-sample.html     pushy shop page     - rates C (72)
├── risky-sample.html       mock rewards page   - rates D (50)
└── spam-sample.html        mock spam page      - rates F (21, 16 findings)
test/analyzer.test.js       22 unit tests (Node.js, optional)
tools/make-icons.js         regenerates the PNG icons (optional)
```

Only the `extension` folder is needed to run it. Everything else is there to demonstrate and
verify the code.

---

## 3. Part 1 — the embedded button

`content.js` is registered in the manifest for `http://*/*`, `https://*/*` and `file:///*`,
so the browser injects it into every page that is visited:

```json
"content_scripts": [{
  "matches": ["http://*/*", "https://*/*", "file:///*"],
  "js": ["js/panel-style.js", "js/spam-analyzer.js", "js/content.js"],
  "run_at": "document_idle"
}]
```

The script then:

* builds the button inside a **shadow root**, so the host page's CSS cannot break the button
  and the extension's CSS cannot leak into the page;
* injects the panel CSS **as text** (`panel-style.js`) rather than linking a `.css` file: a
  stylesheet injected through the manifest does not cross a shadow boundary, and a linked
  `chrome-extension://` stylesheet is blocked on `file:///` pages, which left the button
  unstyled and therefore invisible there;
* labels it `🛡 You are on "<current URL>"` — shortened on the button, full URL in the tooltip
  and in the report;
* keeps the label correct on single page apps, where the address changes without loading a new
  document (`pushState`, `replaceState`, `popstate`, `hashchange`, plus a slow poll as a
  fallback);
* runs in the top document only, and guards against being injected twice.

### Where the button sits

It starts in the bottom right corner, 100px up from the bottom edge rather than flush with it,
because many sites pin their own bar down there.

* **It moves out of the way by itself.** On load (and again a second later, for bars that
  appear late, such as cookie notices) the script hit-tests the point where the button would
  sit. If a fixed or sticky bar is painted there — a chat app's message box, for example — the
  button settles just above it instead of covering it.
* **You can drag it anywhere.** Press and drag the button to any corner; the position is
  remembered for next time and always wins over the automatic placement. A press that moves
  less than 4px still counts as a click, so dragging never opens the report by accident.
* **The report follows.** It normally opens above the button, and flips below or to the right
  if the button has been dragged near the top or the left edge, so it always stays on screen.

## 4. Part 2 — the spam test and the safety rating

Pressing the button (or **Alt+Shift+S**) runs all 49 checks and opens a report showing the
score, the letter rating, every finding with its penalty, and the checks that passed.

**The verdict appears on its own.** The page is checked automatically about half a second
after it loads, so the pill is already coloured when you arrive — a cyan-teal gradient for a
safe site, amber and orange in between, deep red for one that fails. Nothing has to be
clicked, and a single page app that changes its address without reloading is re-checked too.

The label and shield are white on every verdict. That is why the ramps run deep rather than
pastel: white text on bright cyan is unreadable, so the gradient carries its brightness in a
coloured glow around the pill instead of in the fill. The unsafe ramp is the brightest red
that still holds white text — #ef4444 would look hotter but drops to 3.8:1. Measured from
rendered pixels at the text's own height, the safe pill reads 5.25:1 and the unsafe pill
4.69:1, and every piece of text on the rating block stays at 5.1:1 or better.

**Minimising.** A long address makes a wide pill, so the control beside it collapses everything
to a circle showing just the rating letter — the report animates closed alongside it — and
expands it again. The choice is remembered.

**The rating block** in the report is painted with the same gradient as the pill, not a wash of
it — a translucent tint over a dark panel turns any bright colour to mud, which is why the
alarm red read as plum there while the pill was vivid. Text on the block switches to white, while the score
ring, the number inside it and the rating chip share one gradient per verdict: green on the
teal, coral on the red, pale gold and peach on the amber and orange. The ring sits in a dark
groove rather than a light one, which is what lets each verdict use a real tint of its own
colour — on a bright red card a mid red measures 1.28:1 and a pale one reads as white, so
without the groove the arc gets pushed to one extreme or the other. Those are graphics and
large text, where the bar is 3:1; measured on the rendered card the arcs run 3.41:1 to 4.57:1
against the card and 6:1 to 8:1 against the groove, and the chip's ink reaches 7.5:1. The rest of the panel stays neutral: a saturated fill behind
body text would cost more in readability than it gains.

**The counts are jump links.** Clicking *high*, *medium*, *low* or *passed* scrolls the report
to the first check of that kind and flashes it, which matters on a page where sixteen findings
do not fit on screen at once.

**Every check explains itself.** Click any row, passed or failed, and it expands to say what
that check looks for and why it matters, in three or four sentences of plain English. The rows
are `<details>` elements, so the keyboard and screen-reader behaviour comes from the element
rather than from extra code. The rating also appears on the toolbar icon badge.

### The interface

The button and the report are drawn from one small design system defined at the top of
`js/panel-style.js`: a neutral ramp, one accent, and five semantic colours that the score
ring, the rating badge and the findings all share.

* **Themes.** Light and dark are both defined, and the UI follows the reader's system setting
  rather than the colours of whatever page it is sitting on.
* **Contrast.** Every piece of text was measured against the surface behind it and meets
  WCAG AA. The button is translucent, so its contrast depends on the page underneath; measured
  from rendered pixels it ranges from 10.8:1 (dark theme over a light page) to 18.9:1.
* **The score ring** is an SVG arc with round caps that sweeps up to the score, rather than a
  conic gradient, which cannot round its ends and shows a hard seam.
* **The verdict gradients** run deep enough that white text clears AA on every stop, and each
  carries a glow in its own bright hue so the colour still reads as cyan or red at a glance.
* **Motion** follows the curves Apple uses for sheets and popovers — a fast start that settles,
  `cubic-bezier(.32, .72, 0, 1)`, with a small overshoot on anything that appears. The report
  scales up into place and falls back towards the button when it closes; the pill morphs into
  the circle rather than snapping, its label folding away as the width animates. Growth gets
  the spring, shrinking does not: overshooting a shrink means passing *below* the target, which
  reads as a glitch rather than a bounce. Findings and counts arrive staggered 26ms apart, the
  rating letter pops in when a scan lands, the minimise control turns rather than swapping its
  icon, and everything pressable gives slightly under the press. All of it is dropped under
  `prefers-reduced-motion`.
* **The collapsed letter** is centred against the circle rather than laid out beside its
  siblings — the folded label still takes part in the flex line — and measured from rendered
  pixels at 4x it sits within 0.13px of the centre on every verdict.
* **Keyboard and screen readers.** Alt+Shift+S opens the report and Escape closes it, every
  control has a visible focus ring, and the report body is a polite live region so a finished
  scan is announced. The expandable checks are `<details>` elements and the counts are real
  buttons, so both work from the keyboard without extra code.

### The 49 tests

*Scope* **URL** = works from the address alone · **Page** = needs the page content.
An asterisk marks a test that also caps the score (see below).

| # | Test id | Scope | Raised when | Penalty |
|---|---|---|---|---|
| 1 | `https` | URL | Connection is not encrypted | 12 |
| 2 | `ip-host` | URL | Site is addressed by a raw IP address | 12 |
| 3 | `punycode` | URL | Domain uses international characters | 6 |
| 4 | `at-symbol` | URL | Address uses the "@" trick | 10 * |
| 5 | `shortener` | URL | Destination is hidden behind a URL shortener | 6 |
| 6 | `suspicious-tld` | URL | Top level domain is frequently abused | 8 |
| 7 | `brand-impersonation` | URL | Brand name used outside the real domain | 12 |
| 8 | `many-subdomains` | URL | Too many sub-domain levels | 5 |
| 9 | `long-url` | URL | Address is abnormally long | 4 |
| 10 | `hyphen-domain` | URL | Domain looks typo-squatted | 4 |
| 11 | `digits-in-domain` | URL | Domain is padded with digits | 5 |
| 12 | `sensitive-keywords` | URL | Credential-harvesting keywords in the address | 6 |
| 13 | `nonstandard-port` | URL | Unusual network port | 5 |
| 14 | `encoded-chars` | URL | Address is heavily percent-encoded | 4 |
| 15 | `query-complexity` | URL | Unusually complex query string | 3 |
| 16 | `executable-url` | URL | Address points at an executable file | 10 * |
| 17 | `unsafe-scheme` | URL | Page is not loaded from a normal web address | 10 * |
| 18 | `mixed-scripts` | URL | Domain is a look-alike of another name | 12 * |
| 19 | `typosquat-brand` | URL | Domain is a near-miss of a well known brand | 14 * |
| 20 | `tld-in-subdomain` | URL | A domain ending is buried in the sub-domain | 10 * |
| 21 | `redirect-param` | URL | Address carries another URL as a parameter | 7 |
| 22 | `random-domain` | URL | Domain looks machine generated | 6 |
| 23 | `hostname-length` | URL | Host name is abnormally long | 4 |
| 24 | `insecure-password-form` | Page | Password requested over an insecure page | 15 * |
| 25 | `cross-domain-form` | Page | Form submits your data to another site | 10 |
| 26 | `hidden-iframes` | Page | Hidden / zero-sized frames | 8 |
| 27 | `third-party-scripts` | Page | Many third party scripts | 5 |
| 28 | `spam-phrases` | Page | Classic spam wording in the text | 12 |
| 29 | `shouty-text` | Page | Text is written in shouting style | 4 |
| 30 | `obfuscated-js` | Page | Inline scripts look obfuscated | 8 |
| 31 | `meta-refresh` | Page | Page redirects automatically | 6 |
| 32 | `popup-traps` | Page | Pop-up / leave-page traps | 5 |
| 33 | `hidden-text` | Page | Invisible keyword stuffing | 6 |
| 34 | `external-links` | Page | Most links leave this site | 5 |
| 35 | `site-identity` | Page | Page has no proper identity | 3 |
| 36 | `overlay-ads` | Page | Full screen overlay / pop-under | 5 |
| 37 | `auto-download` | Page | Executable file download offered | 8 |
| 38 | `mixed-content` | Page | Insecure resources on a secure page | 7 |
| 39 | `fake-urgency` | Page | Artificial time pressure | 4 |
| 40 | `payment-fields` | Page | Page asks for card or identity details | 12 |
| 41 | `favicon-hotlink` | Page | Site icon is borrowed from another domain | 7 |
| 42 | `title-brand-mismatch` | Page | Page claims a brand that does not own the domain | 12 * |
| 43 | `deceptive-links` | Page | Link text does not match where the link goes | 10 |
| 44 | `full-page-iframe` | Page | Whole page is another site in a frame | 10 |
| 45 | `scareware` | Page | Page uses scare tactics | 12 |
| 46 | `crypto-wallet` | Page | Page shows a crypto wallet address | 9 |
| 47 | `permission-abuse` | Page | Page grabs browser permissions on load | 6 |
| 48 | `ad-density` | Page | Page is dominated by advertising frames | 5 |
| 49 | `contact-info` | Page | No contact information on the page | 3 |

### How the score is calculated

```
riskRatio = penalty points collected / penalty points available
score     = 100 - (riskRatio / 0.40) * 100      clamped to 0…100
score     = min(score, lowest cap among the findings)
```

Three ideas make the number meaningful:

1. **The penalty is measured against the tests that actually ran.** A URL-only scan can run
   only the 23 address tests, so without this a bad URL would look safe simply because the page
   tests were skipped.
2. **`RISK_SPAN = 0.40`** means "a page that collects 40% of the available penalty weight
   scores zero".
3. **Some findings cap the score.** A domain one character away from `paypal.com`, a
   mixed-alphabet host, or a password box on an unencrypted page is close to conclusive on its
   own; averaging it against 48 passing tests would hide it. Those tests hold the score at 30
   to 50 regardless of what else passes.

| Score | Rating | Verdict |
|---|---|---|
| 90–100 | **A** | Safe |
| 75–89 | **B** | Probably safe |
| 60–74 | **C** | Use caution |
| 40–59 | **D** | Suspicious |
| 0–39 | **F** | Likely spam / unsafe |

`report.isSpam` is true below 60.

### Example results

| Address | Score | Why |
|---|---|---|
| `https://www.bbc.co.uk/news` | 100 A | nothing to report |
| `https://münchen.de/` | 91 A | a genuine international domain is not punished |
| `https://example.com/go?url=https://evil.example.tk/x` | 90 A | open redirect parameter noted |
| `https://bit.ly/3xYzAb` | 87 B | a shortener hides the destination |
| `https://paypal.com.secure-verify.tk/login` | 45 D | ".com" buried in the sub-domain |
| `https://paypa1.com/login` | 30 F | one character away from paypal.com |
| `https://pаypal.com/` (Cyrillic а) | 30 F | look-alike domain |
| `test-pages/spam-sample.html` | 21 F | 16 warnings from the page content |

---

## 5. Demonstrating it

1. Load the extension (section 1).
2. Turn on *Allow access to file URLs* (section 1), then open the four pages in `test-pages/`
   and press the button on each. They are built to land in a different band apiece, so you can
   show every colour without hunting for a real site that misbehaves:

   | Page | Score | Rating |
   |---|---|---|
   | `safe-sample.html` | 100 | **A** — Safe, no findings |
   | `caution-sample.html` | 72 | **C** — Use caution, 8 findings |
   | `risky-sample.html` | 50 | **D** — Suspicious, 11 findings |
   | `spam-sample.html` | 21 | **F** — Likely spam, 16 findings |
3. Press the button on any real website to show it working on live pages.

`spam-sample.html` is a harmless mock: the form target does not exist, the "download" link
points at a file that is not in the folder, and the obfuscated-looking script only writes a
string to the console.

## 6. Unit tests (optional)

Requires Node.js 18+; the extension itself needs nothing installed.

```bash
npm test          # 22 tests over the analyser
```

They cover the rating bands, the individual detectors, the score caps, the punycode decoder,
the report bookkeeping, and that odd inputs never throw.

## 7. Limitations

The scanner is a **client-side heuristic**. It never contacts a remote blocklist or reputation
service such as Google Safe Browsing, so it can produce false positives and false negatives:
it is a demonstration of the technique, not real protection. Wording tests were deliberately
split into strong scam vocabulary and ordinary marketing copy so that a normal shop saying
"buy now" or a bank saying "security alert" is not reported as spam. All analysis happens
locally — nothing is uploaded, and no data leaves the browser.
