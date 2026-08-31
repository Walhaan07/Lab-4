# VeriSite — browser extension (Lab 4, Demo 4)

VeriSite is a browser extension that **embeds a button on every page the browser visits**. The button
displays `You are on "URL"`, and pressing it runs **95 tests** on the current site to decide
whether it is phishing, pharming, malware or another kind of scam, and to give it a
**safety rating (A–F, 0–100)**.

| Requirement | Where it is implemented |
|---|---|
| **Part 1** — embed a button on all visited pages showing `You are on "URL"` | `extension/js/content.js` + `extension/manifest.json` |
| **Part 2** — pressing the button tests the site for spam and rates it | `extension/js/spam-analyzer.js` (95 tests), rendered by `content.js` |

The verdict comes from three layers rather than one:

| Layer | File | What it answers |
|---|---|---|
| **Reputation** | `js/threat-intel.js` | *Do we already know this address?* Known-bad addresses and the published anti-malware feature test pages — which no heuristic can catch, because they are ordinary, well made pages on reputable domains. |
| **Heuristics** | `js/spam-analyzer.js` | *How is this page built?* 95 independent tests over the address, the transport, the forms, the wording and the scripts. |
| **Correlation** | `js/spam-analyzer.js` | *Do these findings add up to something?* Six attack patterns that recognise combinations no single test can see. |

A fourth idea runs across all of them: the scanner keeps track of **who wrote the words on the
page**. Typing "show me a congratulations giveaway scam" into an assistant fills the page with
scam vocabulary that the site never said, and the wording tests stand down when that is the
case. See *Context awareness* below.

---

## 1. Loading it in Microsoft Edge

1. Open **`edge://extensions`**.
2. Turn on **Developer mode** (bottom left).
3. Click **Load unpacked**.
4. Select the **`VeriSite`** folder — the one containing `manifest.json`. Do not select the
   folder above it, and do not select the manifest file itself. (In the repository this folder
   is called `extension`; the packaged download names it `VeriSite` so the browser lists it
   that way.)
5. Visit any website. The button appears in the bottom right corner; press it to run the scan.

### To use it on the sample pages (or any page opened from disk)

Pages opened from disk have a `file:///C:/...` address, and **browsers do not run extensions on
those unless you allow it**, one extension at a time:

1. On `edge://extensions`, click **Details** on *VeriSite*.
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
    ├── threat-intel.js     REPUTATION - known addresses, kit fingerprints, hosting classes
    ├── spam-analyzer.js    THE ENGINE - all 95 tests, the patterns and the scoring
    ├── content.js          PART 1 + PART 2 - injected into every page
    ├── panel-style.js      the button / report CSS, injected as text
    ├── background.js       service worker: toolbar badge, per-tab results
    └── popup.js            toolbar popup logic

test-pages/                 eleven self-contained pages
├── safe-sample.html        clean page                  - rates A (100)
├── caution-sample.html     pushy shop page             - rates C (67)
├── risky-sample.html       mock rewards page           - rates D (52)
├── spam-sample.html        mock spam page              - rates F (0, 18 findings)
├── phishing-kit-sample.html    cloned bank sign-in     - rates F, credential kit
├── pharming-sample.html    router / DNS attack page    - rates F, pharming
├── drainer-sample.html     crypto wallet drainer       - rates F, drainer
├── clickfix-sample.html    fake captcha, "press Win+R" - rates F
├── feature-check-sample.html   anti-phishing test page - blocked, recognised dynamically
├── assistant-sample.html   scam words the visitor typed - rates A (context aware)
└── webapp-sample.html      an ordinary application     - rates A (precision guard)
test/analyzer.test.js       27 unit tests over the analyser
test/intel.test.js          20 tests over the reputation layer and the address checks
test/page.test.js           33 tests that need a rendered page (jsdom)
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
* **It opens whichever way there is room.** The pill normally grows leftwards from its anchor,
  with the minimise control on its inner side. Dragged to the left of the window that would open
  it straight off the screen, so the whole dock mirrors: the control travels round the pill —
  along the arc it would trace if it were rolling round it, rather than jumping across — the
  chevron turns to point the new way, and the pill then opens to the right. The timing is a
  **spring**, sampled into keyframes rather than approximated with a curve: a cubic-bezier cannot
  overshoot and settle, and that settle is most of what makes a movement feel like an object
  rather than a value being interpolated. Measured in the browser it covers 69% of the distance
  in the first quarter of its time, lifts 65px over the pill, swells to 1.09× at the apex, and
  lands with a 3% overshoot that is gone by 620ms. The same decision is
  taken again on every drag, every window resize and every time it is opened, and it is taken
  from the room actually available rather than from which half of the screen it is in, with the
  current side keeping its place while it still fits so nothing flaps about mid-drag.
* **It never outgrows its space.** The pill's width is capped to the room beside it, so a long
  address is truncated rather than pushed off the edge — on a 360px phone-width window the pill,
  the control and the report all still fit.
* **The report follows.** It opens on the same side as the pill so the two read as one object,
  above it or below it depending on where the button sits, and is then pulled back inside the
  window if neither side has room for its full width. Its height is capped to the space actually
  available, so it can never overflow however far the button has been dragged.
* **All of that is verified in a real browser**, not asserted on paper: `npm run ui-check` parks
  the button in every corner, at three window sizes, opens and closes the report at each, and
  fails if any part of the interface ends up outside the window (see section 6).

## 4. Part 2 — the spam test and the safety rating

Pressing the button (or **Alt+Shift+S**) runs all 95 checks and opens a report showing the
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

**A recognised threat goes first.** When the reputation layer matches, the report opens with a
red block above the score naming what the address is and where that came from, because at that
point the number is no longer the interesting part. Below the score, any attack pattern the
findings add up to gets its own block, and — where the wording tests stood down — one line
saying why: *"This is an assistant page: the words on screen are written by the people using
it."*

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
* **The report grows out of the button and drops back into it.** Its transform origin is set
  from script to the middle of the button, measured from layout geometry rather than a rect
  (the entrance animation fills backwards, so a measured rect would already be the shrunken
  one). That makes it follow whichever shape the button currently has — the full pill or the
  collapsed circle — and keep tracking it after a drag, with no special cases.
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

### The 95 tests

*Scope* **URL** = works from the address alone · **Page** = needs the page content.
`*` marks a test that also caps the score. `†` marks a wording test that stands down on pages
where the visitor writes the words (see *Context awareness*).

| # | Test id | Category | Scope | Raised when | Penalty |
|---|---|---|---|---|---|
| 1 | `https` | Transport | URL | Connection is not encrypted | 12 |
| 2 | `ip-host` | URL | URL | Site is addressed by a raw IP address | 12 |
| 3 | `punycode` | URL | URL | Domain uses international characters | 3 |
| 4 | `at-symbol` | URL | URL | Address uses the "@" trick | 10 * |
| 5 | `shortener` | URL | URL | Destination is hidden behind a URL shortener | 6 |
| 6 | `suspicious-tld` | URL | URL | Top level domain is frequently abused | 8 |
| 7 | `brand-impersonation` | URL | URL | Brand name used outside the real domain | 12 |
| 8 | `many-subdomains` | URL | URL | Too many sub-domain levels | 5 |
| 9 | `long-url` | URL | URL | Address is abnormally long | 4 |
| 10 | `hyphen-domain` | URL | URL | Domain looks typo-squatted | 4 |
| 11 | `digits-in-domain` | URL | URL | Domain is padded with digits | 5 |
| 12 | `sensitive-keywords` | URL | URL | Credential-harvesting keywords in the address | 6 |
| 13 | `nonstandard-port` | Transport | URL | Unusual network port | 5 |
| 14 | `encoded-chars` | URL | URL | Address is heavily percent-encoded | 4 |
| 15 | `query-complexity` | URL | URL | Unusually complex query string | 3 |
| 16 | `executable-url` | URL | URL | Address points at an executable file | 10 * |
| 17 | `unsafe-scheme` | Transport | URL | Page is not loaded from a normal web address | 10 * |
| 18 | `mixed-scripts` | URL | URL | Domain is a look-alike of another name | 12 * |
| 19 | `typosquat-brand` | URL | URL | Domain is a near-miss of a well known brand | 14 * |
| 20 | `tld-in-subdomain` | URL | URL | A domain ending is buried in the sub-domain | 10 * |
| 21 | `redirect-param` | URL | URL | Address carries another URL as a parameter | 7 |
| 22 | `random-domain` | URL | URL | Domain looks machine generated | 6 |
| 23 | `hostname-length` | URL | URL | Host name is abnormally long | 4 |
| 24 | `insecure-password-form` | Forms | Page | Password requested over an insecure page | 15 * |
| 25 | `cross-domain-form` | Forms | Page | Form submits your data to another site | 10 |
| 26 | `hidden-iframes` | Content | Page | Hidden / zero-sized frames | 8 |
| 27 | `third-party-scripts` | Content | Page | Many third party scripts | 5 |
| 28 | `spam-phrases` | Content | Page | Classic spam wording in the text | 15 † |
| 29 | `shouty-text` | Content | Page | Text is written in shouting style | 4 † |
| 30 | `obfuscated-js` | Scripts | Page | Inline scripts are obfuscated | 8 |
| 31 | `meta-refresh` | Content | Page | Page redirects automatically | 6 |
| 32 | `popup-traps` | Scripts | Page | Pop-up / leave-page traps | 5 |
| 33 | `hidden-text` | Content | Page | Invisible keyword stuffing | 6 |
| 34 | `external-links` | Content | Page | Most links leave this site | 5 † |
| 35 | `site-identity` | Content | Page | Page has no proper identity | 3 |
| 36 | `overlay-ads` | Content | Page | Advertising overlays the content | 5 |
| 37 | `auto-download` | Downloads | Page | Executable file download offered | 8 |
| 38 | `mixed-content` | Transport | Page | Insecure resources on a secure page | 7 |
| 39 | `fake-urgency` | Content | Page | Artificial time pressure | 4 † |
| 40 | `payment-fields` | Forms | Page | Page asks for card or identity details | 12 |
| 41 | `favicon-hotlink` | Content | Page | Site icon is taken from another company | 7 |
| 42 | `title-brand-mismatch` | Content | Page | Page claims a brand that does not own the domain | 12 * |
| 43 | `deceptive-links` | Content | Page | Link text does not match where the link goes | 10 † |
| 44 | `full-page-iframe` | Content | Page | Whole page is another site in a frame | 10 |
| 45 | `scareware` | Content | Page | Page uses scare tactics | 12 † |
| 46 | `crypto-wallet` | Content | Page | Page shows a crypto wallet address | 9 † |
| 47 | `permission-abuse` | Scripts | Page | Page grabs browser permissions on load | 6 |
| 48 | `ad-density` | Content | Page | Page is dominated by advertising frames | 5 |
| 49 | `contact-info` | Content | Page | No contact information on the page | 3 |
| 50 | `known-threat` | Reputation | URL | Address is on a known-threat list | 25 |
| 51 | `test-page-signature` | Reputation | Page | Page is a published security feature test | 20 † |
| 52 | `kit-path` | URL | URL | Path matches a known phishing-kit shape | 12 |
| 53 | `brand-in-domain` | URL | URL | Domain borrows a well known company name | 16 * |
| 54 | `homograph-brand` | URL | URL | Domain spells a brand in look-alike letters | 18 * |
| 55 | `free-subdomain-host` | Reputation | URL | Published on a throwaway free sub-domain | 6 |
| 56 | `dynamic-dns-host` | Reputation | URL | Hosted behind a dynamic DNS name | 8 |
| 57 | `credential-in-url` | URL | URL | Address carries a personal identifier | 8 |
| 58 | `double-extension` | URL | URL | File name hides a second extension | 12 * |
| 59 | `archive-download` | URL | URL | Address is a direct archive download | 5 |
| 60 | `private-network-target` | Network | Page | Page points at private network addresses | 14 * |
| 61 | `router-attack` | Network | Page | Page aims requests at your router | 14 |
| 62 | `dns-change-instructions` | Network | Page | Page talks you through changing DNS settings | 12 † |
| 63 | `redirect-chain` | Network | Page | Reached through a chain of redirects | 6 |
| 64 | `downgraded-form` | Forms | Page | Form drops out of the encrypted connection | 14 * |
| 65 | `form-to-ip` | Forms | Page | Form posts to a bare IP address | 14 * |
| 66 | `mailto-form` | Forms | Page | Form e-mails your details straight to someone | 16 * |
| 67 | `credential-exfil` | Scripts | Page | Page scripts post your data to a collector | 20 * |
| 68 | `credential-brand-mismatch` | Forms | Page | Sign-in page wears another company's identity | 20 * |
| 69 | `otp-harvest` | Forms | Page | Page collects a one-time code as well as a password | 12 |
| 70 | `seed-phrase-harvest` | Forms | Page | Page asks for your wallet recovery phrase | 22 * † |
| 71 | `wallet-drainer` | Scripts | Page | Page scripts ask your wallet to sign an approval | 18 * |
| 72 | `hidden-password-field` | Forms | Page | Page hides a password field | 7 |
| 73 | `id-document-upload` | Forms | Page | Page asks you to upload identity documents | 10 † |
| 74 | `keystroke-capture` | Scripts | Page | Page scripts record what you type | 12 |
| 75 | `login-form-no-action` | Forms | Page | Sign-in form has no real destination | 8 |
| 76 | `srcdoc-credential-frame` | Forms | Page | Password field hidden inside a written-in frame | 12 |
| 77 | `cloned-brand-assets` | Content | Page | Page borrows another company's images and styles | 14 * |
| 78 | `fake-address-bar` | Content | Page | Page draws a fake address bar | 12 * |
| 79 | `fake-security-seal` | Content | Page | Page shows an unverifiable security badge | 7 † |
| 80 | `clickfix-clipboard` | Scripts | Page | Page talks you into running a command yourself | 20 * † |
| 81 | `fake-captcha` | Content | Page | Page fakes a human-verification prompt | 10 † |
| 82 | `fake-update-prompt` | Content | Page | Page pushes a fake software update | 12 † |
| 83 | `tech-support-number` | Content | Page | Support number displayed next to a scare message | 10 † |
| 84 | `install-prompt` | Content | Page | Page offers a direct install package | 10 |
| 85 | `gift-card-payment` | Content | Page | Page asks for payment in gift card codes | 12 † |
| 86 | `giveaway-doubling` | Content | Page | Page promises to send back more than you send | 14 * † |
| 87 | `investment-guarantee` | Content | Page | Page promises guaranteed investment returns | 9 † |
| 88 | `survey-prize` | Content | Page | Page claims you have won something | 8 † |
| 89 | `qr-payment` | Content | Page | QR code shown next to a payment request | 8 † |
| 90 | `subscription-trap` | Content | Page | Recurring charge buried in small print | 7 † |
| 91 | `devtools-blocking` | Scripts | Page | Page blocks inspection of itself | 9 |
| 92 | `bot-cloaking` | Scripts | Page | Page shows something different to scanners | 10 |
| 93 | `dynamic-script-injection` | Scripts | Page | Page hides where its scripts come from | 8 |
| 94 | `history-trap` | Scripts | Page | Page traps the back button | 7 |
| 95 | `data-uri-navigation` | Content | Page | Page links to inline documents or script | 10 |

### The reputation layer

Some pages cannot be judged by how they are built. The industry anti-phishing feature test page
is the clearest case: valid HTML, a reputable domain, a plain explanation of what it is for, and
every structural test passes it — the first version of this extension rated it **93, A**. That is
not a scoring mistake, it is a category mistake. A product recognises that page because it knows
what it is, and the page itself says so when it loads: *"If you can read this page, your
anti-phishing feature is not enabled."*

**No host is named anywhere in the feed.** Listing amtso.org would only ever have recognised the
test pages that existed the day it was written, and would have said nothing about the next
vendor's. Two host-agnostic mechanisms are used instead:

1. **The address describes the test.** `check-desktop-phishing-page`, `feature-settings-check`,
   `its-a-trap`, `eicar`, `malware-test` — these are descriptions, and they work on whatever
   domain they turn up on. They come in two strengths, because `check-desktop-phishing-page` can
   only be one thing while `/blog/phishing-test-page-explained` is probably an article.
2. **The page says so itself.** Three families of wording are scored: what the page claims to be
   ("test page", "feature settings check"), which protection it is testing ("anti-phishing",
   "safe browsing"), and — the giveaway — that you were not supposed to get this far ("if you
   can read this", "is not enabled", "did not block"). That third family is what separates a page
   that **is** a test from a page **about** one, because an article's readers are not people
   whose protection just failed.

Neither alone is treated as proof unless it is unambiguous:

| Evidence | Result |
|---|---|
| Page says you should not be reading it | **Blocked** on any host, in any wording |
| Address unambiguously names a test **and** the page agrees | **Blocked** |
| Address unambiguously names a test, page not read (address-only scan) | **Blocked** |
| Address could belong to an article, nothing in the page confirms it | reported, ~8 points, **not** blocked |

The rest of the feed is about kits rather than sites: exfiltration endpoints (Telegram bots,
Discord webhooks, `mailto:` form actions), kit path shapes, throwaway hosting classes, and which
domains each brand really runs — so `outlook.live.com` and `s3.amazonaws.com` are not read as
impersonation. Plus a local block list an administrator or the user fills themselves:

```js
chrome.storage.local.set({blockList: [
    'phishing-example.com',                       // whole host
    '/payroll-update-2026',                       // any address containing this path
    {match: 'https://bad.example.com/login',      // exact prefix, with your own wording
     kind: 'phishing', label: 'Reported by IT',
     detail: 'Added after a reported incident.'}
]});
```

The list is read once per page load, so reload the tab to apply it. When anything here matches,
the report opens with a red block naming the threat and the toolbar badge changes from a grade
to **!**.

### Context awareness — who wrote the words on the page

A wording test asks *"what is this page claiming?"*. On an assistant, a search results page, an
inbox or a forum, that question has no meaning: the words belong to whoever is using the site.
Asking a chatbot for examples of giveaway scams should not make the chatbot look like one.

Two mechanisms keep that straight:

1. **Authorship is split before any wording test runs.** Text inside inputs, text areas,
   editable regions, chat message nodes, comments, quotes and code blocks is removed from the
   page's own copy, along with anything that came from the address bar's query (`?q=…`,
   `?prompt=…`). What remains is what the *site* says.
2. **Interactive pages are recognised, listed or not.** Assistants, search engines, webmail,
   social networks, forums and marketplaces are recognised by host; anything else showing a
   composer plus a conversation, feed or results list is recognised by shape. On those pages the
   22 wording tests are *skipped rather than answered wrongly*, and the report says why.

Structural tests — transport, address, forms, scripts, reputation — always run. Context
awareness never becomes a way through: a page that says the scam words in its own copy, with no
visitor to blame, is still caught.

### Attack patterns

Some findings mean little apart and a great deal together. A password box is ordinary; a
password box on a free sub-domain wearing a bank's logo is a phishing kit.

| Pattern | Recognised from |
|---|---|
| **Credential harvesting kit** | something collecting a password + a disposable host + somebody else's identity |
| **Pharming / redirected traffic** | private-network or router targets + an insecure or mismatched sign-in |
| **Crypto wallet drainer** | wallet machinery + borrowed branding or a promise of free money |
| **Fake support / scareware** | an invented device warning + something that keeps you on the page |
| **Malware delivery page** | something that installs + something that hides how the page works |
| **Prize / advance-fee scam** | an offer nobody makes + a disposable or anonymous publisher |
| **Page hiding how it works** | three or more of: packed code, run-time assembly, visitor checks, blocked developer tools |

A finding may only answer for one group of a pattern, so a single look-alike domain cannot
satisfy two conditions at once and invent a pattern out of one fact.

### Precision — what a finding has to prove

Version 2 rated google.com, an assistant and essentially every modern application **F**. The
cause was the same each time, and it is worth writing down because it is the standard way a
scanner like this goes wrong:

> A test asked whether two tokens appeared **anywhere** in the page's scripts. In a bundled
> application, every token appears somewhere: a key listener here, a `fetch` there, a base64
> decode in a helper, `createElement('script')` in the chunk loader. The answer was always yes.

Every behavioural test now asks whether the things appear **together**, inside one window of
code, and whether there is anything for them to act on:

| Test | Version 2 asked | Now asks |
|---|---|---|
| `keystroke-capture` | is there a key listener, and a `fetch`, and a `.value`? | on a page with a password or card field: does a key handler send what was typed, in the same breath, to **another** site? |
| `history-trap` | is there a `pushState` and a `popstate`? | does a `popstate` handler send you **forward** again, or does a loop flood the history? |
| `dynamic-script-injection` | is there a `createElement('script')` and a decode? | is a script's **address** built from encoded text, in the same window? |
| `obfuscated-js` | are `atob` and `fromCharCode` present? | is something decoded and then **executed**, or is there a long encoded block next to a decoder? |
| `bot-cloaking` | is `navigator.webdriver` mentioned? | does that check decide **what the page shows**? |
| `devtools-blocking` | are two devtools-ish tokens present? | are the right-click menu **and** the devtools keys both blocked? |
| `install-prompt` | does the page link to a `.pkg`, `.apk`, `.deb`? | is the installer from **somewhere other than** this site? |

Three more went the same way for the same reason. `credential-exfil`, `wallet-drainer` and
`router-attack` used to read the page's raw markup, which meant an article explaining an attack —
code samples and all — read as the attack itself. They now read only executable script, form
targets and where the page actually points. `seed-phrase-harvest` used to fire on any page
mentioning a recovery phrase, which is every exchange's own security warning; it now needs a
field that collects one, and stands down entirely when the page is telling you never to share it.

Two structural changes support all of that: `<script type="application/json">` and other data
blocks are no longer read as code, and a page's visible text no longer includes the source of its
scripts.

**The same lesson again, on the page rather than in the scripts.** Version 3 rated google.com a
**C**, a Google search an **F**, and claude.ai *use caution*. Four causes, and the fourth is the
one worth remembering:

| Test | Version 3 asked | Now asks |
|---|---|---|
| `favicon-hotlink` | is the tab icon on another domain? | is it on a **brand's** domain, while the page is not that brand? Serving your icon from your own CDN — gstatic for Google, an asset host for everybody else — is ordinary, and no list of every company's CDN could ever be complete. |
| `hidden-text` | is there text with `display:none`? | is it hidden by a *stuffing* technique — sized to nothing, coloured to the background, indented off the page? `display:none` is how every menu, dialog and tab panel is built; counting it reported 39,000 hidden characters on google.com. |
| `overlay-ads` | is there a floating layer? | is the floating layer an **advert** — ad markup, or an ad network's frame inside it? |
| `hidden-iframes` | are there invisible frames? | is a frame *large enough to click* loaded invisibly (the clickjacking shape)? Zero-sized frames are tracking pixels, and half the web serves them. |
| `kit-path` | is there a long base64-ish value in the query? | *(removed)* Google's own `ved=` parameter matched it. Encoding something is not hiding it. |

And the structural one: **a pattern now requires the thing it is named after.** "Credential
harvesting kit" needed any two of its three groups, so a borrowed favicon plus a kit-shaped
address added up to a phishing kit — on a search engine, with no password field anywhere on the
page. Each pattern now names a defining group that must be present: no credential collector, no
credential kit; no wallet machinery, no drainer.

Finally, the shape of an address — its length, its punctuation, how many parameters it carries —
is now classed as nuisance rather than danger. Every search result, ad click and analytics link
is long and heavily parameterised, and none of them is dangerous for it. Those signals still
count towards a pattern; they just cannot take an honest page out of the safe band on their own.

### How the score is calculated

```
penalty = threat findings
        + min(nuisance findings, 12)      hygiene budget
        + attack patterns
score   = 100 - (penalty / budget) * 100  budget = 60 (page scan) or 35 (address only)
score   = min(score, lowest cap among the findings and patterns)
```

Four ideas make the number meaningful:

1. **The budget is fixed, not proportional to the suite.** Dividing the penalty by the total
   weight of the tests — as version 1 did — means that every test added makes every existing
   finding count for less. A scanner should get sharper as it learns to look for more, not
   gentler, so the penalty is measured against a fixed points budget instead.
2. **Nuisance findings share a small budget of their own.** Advertising, tracker sprawl, no
   contact page: annoying, not dangerous. Those findings can cost at most 12 points between
   them, so an ad-heavy newspaper stays in the safe band while genuine risk still moves the
   score.
3. **Some findings cap the score.** A known address, a domain one character from `paypal.com`,
   a page asking for a wallet's recovery phrase: averaging those against ninety passing tests
   would hide them, so 23 of the tests hold the score down regardless of what else passed.
4. **A reputation hit is not a matter of degree.** It is a name already known, and the report
   says so instead of quoting a number.

| Score | Rating | Verdict |
|---|---|---|
| 90–100 | **A** | Safe |
| 75–89 | **B** | Probably safe |
| 60–74 | **C** | Use caution |
| 40–59 | **D** | Suspicious |
| 0–39 | **F** | Likely spam / unsafe |

`report.isSpam` is true below 60; `report.blocked` is true when the reputation layer matched.

### Example results

| Address | Score | Why |
|---|---|---|
| `https://www.bbc.co.uk/news` | 100 A | nothing to report |
| any modern web application (`test-pages/webapp-sample.html`) | 100 A | routing, telemetry, lazy chunks and minified helpers are not evidence |
| `https://www.google.com/` | 100 A | hidden menus, suggestion layers and a CDN icon are not findings |
| a Google search result page | 88 B | only its 452-character address counts, and only as nuisance |
| `https://chatgpt.com/c/…` (asking about scams) | 100 A | the scam words are the visitor's, not the site's |
| an exchange page warning you never to share your seed phrase | 100 A | warning against a thing is not asking for it |
| an article explaining how drainers work, with code samples | 100 A | prose about code is not code |
| `https://accounts.google.com/signin` | 100 A | a brand's own sign-in page is not "credential keywords" |
| `https://outlook.live.com/mail/0/` | 100 A | Microsoft really does run `live.com` |
| `https://münchen.de/` | 91 A | a genuine international domain is not punished |
| `https://bit.ly/3xYzAb` | 83 B | a shortener hides the destination |
| `https://www.amtso.org/check-desktop-phishing-page/` | **6 F, blocked** | the address names a feature check and the page agrees |
| `https://blog.example.com/phishing-test-page-explained` | 77 B | the address could belong to an article, and the page reads like one |
| `https://paypal-billing-support.com/signin` | 20 F | the brand is inside the registrable domain |
| `https://files.example.com/invoice.pdf.exe` | 30 F | a `.pdf` that is really an `.exe` |
| `https://paypa1.com/login` | 30 F | one character away from paypal.com |
| `https://pаypal.com/` (Cyrillic а) | 6 F | reads as `paypal.com` in look-alike letters |
| `https://paypal.com.secure-verify.tk/login` | 0 F | ".com" buried in the sub-domain |

---

## 5. Demonstrating it

1. Load the extension (section 1).
2. Turn on *Allow access to file URLs* (section 1), then open the pages in `test-pages/` and
   press the button on each. They are built to show a different behaviour apiece:

   | Page | Result | What it demonstrates |
   |---|---|---|
   | `safe-sample.html` | 100 **A** | a clean page, no findings |
   | `caution-sample.html` | 67 **C** | advertising, trackers and hard-sell copy |
   | `risky-sample.html` | 52 **D** | borrowed icon, auto-redirect, link farm |
   | `spam-sample.html` | 0 **F** | 18 findings and 5 attack patterns at once |
   | `phishing-kit-sample.html` | 0 **F** | a cloned sign-in page: brand mismatch, one-time code harvesting, a Telegram collector — the **credential kit** pattern |
   | `pharming-sample.html` | 0 **F** | a page working on your router and DNS — the **pharming** pattern |
   | `drainer-sample.html` | 0 **F** | recovery phrase and wallet approvals — the **drainer** pattern |
   | `clickfix-sample.html` | 8 **F** | a fake captcha talking you into running a command |
   | `feature-check-sample.html` | **blocked** | recognised as a security feature test page by its wording alone |
   | `assistant-sample.html` | 95 **A** | a transcript full of scam words that the *visitor* asked about |
   | `webapp-sample.html` | 100 **A** | an ordinary application — the shape that version 2 rated F |
3. Open `https://www.amtso.org/check-desktop-phishing-page/` to see the reputation layer on the
   live page this release was built for: the badge shows **!**, and the report opens with
   *Known phishing page*.
4. Press the button on any real website to show it working on live pages.

Every sample is a harmless mock. The "malicious" scripts in the kit, drainer and ClickFix pages
are `<script type="text/plain">`, which no browser executes — they are there so the scanner has
something to find. No form target exists, and nothing is downloaded, copied or sent anywhere.

## 6. Publishing it to a store

The folder you load unpacked is not the package a store accepts. Two things differ, and both
fail validation rather than review:

* **`manifest.json` has to be at the root of the zip.** Zipping the folder itself puts it one
  level down.
* **The manifest's `description` is capped at 132 characters** (the name at 45). A description
  written for a README will be rejected on upload.

`npm run store-package` builds it correctly: it checks those limits first and refuses to build a
package that would be rejected, copies only the files the manifest actually points at — no
second manifest, no documentation — and writes `dist/VeriSite-<version>.zip` with the manifest
at the root. `npm run store-package -- --firefox` does the same from the Firefox manifest.

Two more things a reviewer will ask about, worth knowing before you submit:

* **Why the extension needs every site.** It rates the page you are looking at, so it has to be
  able to read the page you are looking at. That is the whole justification, and it is why
  `host_permissions` covers `http://*/*` and `https://*/*`.
* **What it sends.** Nothing. There are no `fetch`, `XMLHttpRequest`, `sendBeacon` or
  `WebSocket` calls anywhere in the shipped code, no remote scripts, and no `eval`. Every check
  runs against the page already in your browser, which is also why the report says so.

The permissions are `storage` and `activeTab` only.

## 7. Unit tests (optional)

Requires Node.js 18+; the extension itself needs nothing installed.

```bash
npm install       # optional: installs jsdom, which enables the page tests
npm test          # 80 tests
npm run ui-check  # optional: drives the interface in a real browser
```

- `analyzer.test.js` — rating bands, individual detectors, score caps, the punycode decoder,
  report bookkeeping, and that odd inputs never throw.
- `intel.test.js` — the feature test pages, the local block list, brand ownership, kit paths,
  the fixed-budget scoring model, that a pattern needs separate findings per group, and that
  the manifest really loads the two engine files in the order they depend on.
- `page.test.js` — needs a rendered page, so it uses **jsdom**. If jsdom is not installed the
  file skips instead of failing. It covers the context-awareness cases (assistant, unlisted chat
  app, search results), the credential kit, pharming, drainer and ClickFix pages, and — in a
  block of its own — precision: an ordinary application, a card formatter that is not a
  keylogger, a router that is not a back-button trap, minified code that is not packed, an
  exchange warning that is not a request, an article that is not the attack it describes, and an
  ad-heavy newspaper that is not a scam. Each of those has its opposite number asserted in the
  same test, so precision cannot be bought by simply detecting less.
- `npm run ui-check` — a separate script, because geometry is the one thing the unit tests
  cannot see: jsdom has no layout, so *"does the report open off the side of the screen?"* can
  only be answered by a browser. It drives the real interface in Chromium through **Playwright**
  (also optional — without it the script says so and exits cleanly) and checks that the dock,
  the toggle, the pill and the report all stay inside the window in every corner and at window
  sizes down to 360×640.

## 8. Limitations

The scanner runs **entirely in the browser**. Nothing is uploaded and no address is ever sent
anywhere, which is a deliberate privacy choice and also the limit of what it can know:

- **There is no live lookup.** Nothing is checked against Google Safe Browsing, PhishTank or any
  other service, so a phishing site registered this morning is judged by its shape alone. That is
  what the 95 heuristics and the seven patterns are for, and it is why the local block list
  exists. The reputation layer recognises *kinds* of page rather than a list of sites, which is
  what lets it keep working as those sites change — but it cannot know that a particular domain
  went bad yesterday.
- **Heuristics produce false positives and false negatives.** A great deal of care has gone into
  the first kind — scam vocabulary is separated from ordinary marketing copy, nuisance findings
  share a capped budget, a brand's own domains are known, and pages whose words belong to their
  visitors are recognised — but a determined page that looks entirely ordinary will still pass.
- **It reads the page, not the network.** It cannot inspect the TLS certificate chain, resolve a
  name to see where it really points, or watch what a script does after the scan.
- **A page it cannot read is a page it cannot judge.** Every test is run inside a guard, and so
  is the reading of the page itself, so a document that is detached, torn down mid-navigation or
  simply hostile degrades to an address-only scan rather than taking the whole scan down. The
  address tests still have plenty to say, but the page tests are reported as skipped, not passed.

It is a demonstration of the technique, and a good one to reason with, but it is not a
replacement for the protection built into the browser.
