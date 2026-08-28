# Lab 4 — Demo 4: Site Safety Checker

A browser extension that **embeds a button on every page the browser visits**. The button
displays `You are on "URL"`, and pressing it runs **33 tests** on the current site to decide
whether it is spam / phishing and to give it a **safety rating (A–F, 0–100)**.

The repository is a **NetBeans HTML5/JavaScript Application with Node.js**, so the same
analyser can be run and demonstrated from inside the IDE without installing the extension.

| Requirement | Where it is implemented |
|---|---|
| **Part 1** — embed a button on all visited pages showing `You are on "URL"` | `extension/js/content.js` + `extension/manifest.json` |
| **Part 2** — pressing the button tests the site for spam and rates it | `src/spam-analyzer.js` (33 tests), rendered by `content.js` |

---

## 1. Project layout

```
Lab-4/
├── nbproject/                 NetBeans project metadata (HTML5/JS + Node.js)
├── package.json               npm scripts: start / test / sync / icons
├── server.js                  static server for public_html (Node core only, no deps)
│
├── src/
│   └── spam-analyzer.js       THE ENGINE — 33 spam / phishing tests (edit this one)
│
├── extension/                 <-- load this folder in the browser
│   ├── manifest.json          Manifest V3 (Chrome / Edge)
│   ├── manifest.firefox.json  Manifest V3 variant for Firefox
│   ├── popup.html
│   ├── css/panel.css          styles for the injected button + report panel
│   ├── css/popup.css
│   ├── icons/                 generated PNG icons
│   └── js/
│       ├── spam-analyzer.js   copy of src/spam-analyzer.js (npm run sync)
│       ├── content.js         PART 1 + PART 2 — injected into every page
│       ├── background.js      MV3 service worker: badge + per-tab results
│       └── popup.js           toolbar popup
│
├── public_html/               NetBeans site root (the demo web app)
│   ├── index.html             demo page: test any URL, or scan the page
│   ├── safe-sample.html       clean test page      (scores A / B)
│   ├── spam-sample.html       mock spam test page  (scores F)
│   ├── css/style.css
│   └── js/demo.js, js/spam-analyzer.js
│
├── test/analyzer.test.js      unit tests (node:test)
└── tools/                     sync-shared.js, make-icons.js
```

`src/spam-analyzer.js` is the **single source of truth**. `npm run sync` copies it into
`extension/js/` and `public_html/js/`; both copies are committed so the project works
straight after cloning.

---

## 2. Running the NetBeans project

1. **File ▸ Open Project…** and select the `Lab-4` folder (NetBeans shows it as an
   HTML5/JS application — `nbproject/` is already committed).
2. Site root is `public_html`, the Node.js start file is `server.js`.
3. **Run** the project, or from a terminal:

   ```bash
   npm start          # http://localhost:8383/
   npm test           # runs the 10 unit tests
   ```

The server uses only Node core modules, so **no `npm install` is needed**.

---

## 3. Installing the extension

### Chrome / Edge (Manifest V3)

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension` folder of this project.
4. Visit any website — the button appears in the bottom right corner.

### Firefox

1. Rename `extension/manifest.firefox.json` to `manifest.json` (keep a copy of the Chrome one).
   It is the same manifest plus the required `browser_specific_settings.gecko.id` and an
   event page instead of a service worker.
2. Open `about:debugging#/runtime/this-firefox`.
3. **Load Temporary Add-on…** and select that `manifest.json`.

> To test on local `file://` pages in Chrome, switch on *Allow access to file URLs* on the
> extension's details page. Browsers block extensions on their own internal pages
> (`chrome://`, `about:`, the Web Store), so the button will not appear there — this is a
> browser restriction, not a bug.

---

## 4. Part 1 — the embedded button

`content.js` is registered in the manifest for `http://*/*`, `https://*/*` and `file:///*`,
so the browser injects it into every page that is visited:

```json
"content_scripts": [{
  "matches": ["http://*/*", "https://*/*", "file:///*"],
  "js": ["js/spam-analyzer.js", "js/content.js"],
  "run_at": "document_idle"
}]
```

The script then:

* builds the button inside a **shadow root**, so the host page's CSS cannot break the button
  and the extension's CSS cannot leak into the page;
* labels it `🛡 You are on "<current URL>"` (shortened on the button, full URL in the tooltip
  and in the report);
* runs in the top document only, and guards against being injected twice.

## 5. Part 2 — the spam test and the safety rating

Pressing the button runs all 33 tests and opens a report panel showing the score, the letter
rating, every warning with its penalty, and the list of tests that passed. The rating also
appears on the button and on the toolbar icon badge.

### The 33 tests

*Scope* **URL** = works from the address alone · **Page** = needs the page content.

| # | Test id | Category | Scope | Raised when | Penalty |
|---|---|---|---|---|---|
| 1 | `https` | Transport | URL | Connection is not encrypted | 12 |
| 2 | `ip-host` | URL | URL | Site is addressed by a raw IP address | 12 |
| 3 | `punycode` | URL | URL | Domain uses look-alike (punycode) characters | 10 |
| 4 | `at-symbol` | URL | URL | Address uses the "@" trick | 10 |
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
| 16 | `executable-url` | URL | URL | Address points at an executable file | 10 |
| 17 | `insecure-password-form` | Forms | Page | Password requested over an insecure page | 15 |
| 18 | `cross-domain-form` | Forms | Page | Form submits your data to another site | 10 |
| 19 | `hidden-iframes` | Content | Page | Hidden / zero-sized frames | 8 |
| 20 | `third-party-scripts` | Content | Page | Many third party scripts | 5 |
| 21 | `spam-phrases` | Content | Page | Classic spam wording in the text | 12 |
| 22 | `shouty-text` | Content | Page | Text is written in shouting style | 4 |
| 23 | `obfuscated-js` | Scripts | Page | Inline scripts look obfuscated | 8 |
| 24 | `meta-refresh` | Content | Page | Page redirects automatically | 6 |
| 25 | `popup-traps` | Scripts | Page | Pop-up / leave-page traps | 5 |
| 26 | `hidden-text` | Content | Page | Invisible keyword stuffing | 6 |
| 27 | `external-links` | Content | Page | Most links leave this site | 5 |
| 28 | `site-identity` | Content | Page | Page has no proper identity | 3 |
| 29 | `overlay-ads` | Content | Page | Full screen overlay / pop-under | 5 |
| 30 | `auto-download` | Downloads | Page | Executable file download offered | 8 |
| 31 | `mixed-content` | Transport | Page | Insecure resources on a secure page | 7 |
| 32 | `fake-urgency` | Content | Page | Artificial time pressure | 4 |
| 33 | `contact-info` | Content | Page | No contact information on the page | 3 |

### How the score is calculated

```
riskRatio = penalty points collected / penalty points available
score     = 100 - (riskRatio / 0.40) * 100      clamped to 0…100
```

The penalty is measured against the tests that **actually ran**. A URL-only scan can only run
the 16 address tests (116 of the 230 available points), so without this normalisation every
URL would look safe simply because the page tests were skipped. `RISK_SPAN = 0.40` means
"a page that collects 40% of the available penalty weight scores zero".

| Score | Rating | Verdict |
|---|---|---|
| 90–100 | **A** | Safe |
| 75–89 | **B** | Probably safe |
| 60–74 | **C** | Use caution |
| 40–59 | **D** | Suspicious |
| 0–39 | **F** | Likely spam / unsafe |

`report.isSpam` is true below 60.

### Example results

| Address | Score | Rating |
|---|---|---|
| `https://www.bbc.co.uk/news` | 100 | A — Safe |
| `https://bit.ly/3xYzAb` | 87 | B — shortener hides the destination |
| `http://192.168.4.12:8899/login/verify/account/update` | 25 | F — raw IP, no HTTPS, odd port |
| `http://paypal.secure-login.verify-account.tk/webscr?cmd=login` | 18 | F — brand outside the real domain |
| `public_html/spam-sample.html` (full page scan) | 0 | F — 14 warnings |

---

## 6. Demonstrating it

1. `npm start`, then open <http://localhost:8383/>.
2. **Without the extension:** the demo page loads the same analyser, so you can test any URL
   in the input box or press *Scan this page* to run all 33 tests on the page itself.
3. **With the extension:** open `safe-sample.html` and `spam-sample.html` and press the
   injected button on each. The clean page rates B (it loses points only because localhost is
   served over plain HTTP), the mock spam page rates **F with 14 warnings**.

`spam-sample.html` is a harmless mock: the form target does not exist, the "download" link
points at a file that is not in the repository, and the obfuscated-looking script only writes
a string to the console.

## 7. Unit tests

```bash
npm test
```

10 tests in `test/analyzer.test.js` cover the rating bands, the individual detectors
(IP host, punycode, `@` trick, shortener, executable URL, brand impersonation), the
public-suffix handling, the skipped-test bookkeeping and the 0–100 clamp.

## 8. Limitations

The scanner is a **client-side heuristic** written for a lab exercise. It never contacts a
remote blocklist or reputation service such as Google Safe Browsing, so it can produce false
positives (a legitimate site on a `.xyz` domain) and false negatives (a well-built phishing
page on a clean HTTPS domain). It is a demonstration of the technique, not real protection.
All analysis happens locally — nothing is uploaded.
