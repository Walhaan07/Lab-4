# Store listing copy — VeriSite 6.0.0

Paste these into Partner Center → Store listings. Every number here is checked
against what the extension actually does (`npm run corpus`, `npm test`). If the
behaviour changes, change this too.

---

## Short description (132 character limit)

Shows the URL of every page you visit and rates it for phishing, pharming and scam risk. 100 checks, all in your browser.

---

## Description

VeriSite puts a small button on every page you visit. It shows the address you
are really on and rates the site out of 100, with a grade from A to F. Press it
and the full report opens: every check that ran, what it looks for, and what it
found — in plain English.

It runs 100 checks in three layers: the address, the page itself (its forms,
wording, scripts and frames), and nine attack patterns that no single check can
see alone. A password box is ordinary; a password box on a throwaway sub-domain
wearing a bank's logo is a phishing kit.

Among the things it recognises: look-alike names such as paypa1.com or faceb00k,
cloned sign-in pages, forms that quietly post your details somewhere else,
pages meddling with your router's settings, crypto wallet-drainers, fake
CAPTCHAs and update prompts, tech-support scares, and prize and giveaway scams.

It also tries hard not to cry wolf. Search results, assistants, inboxes and
forums are full of words the site never wrote, so 22 of the wording checks stand
down there — and the report tells you when they did. A news article about scams,
a bank's own fraud guide and a company's own sign-in page are all recognised for
what they are.

Everything happens in your browser. No account, no tracking, and no network
requests of any kind — nothing about the pages you visit ever leaves your
computer.

VeriSite is a second opinion, not a replacement for the protection built into
your browser. It has no live blocklist, so a site registered this morning is
judged on how it is built rather than on what is known about it. It will
sometimes miss something, and occasionally flag something harmless. Leave
Microsoft Defender SmartScreen switched on.

---

## How it measures up (optional — for the listing or a reviewer)

Measured rather than claimed, against 234 live phishing addresses from
OpenPhish and 115 ordinary ones chosen to look like them — real projects on the
same free hosting, real shops on the same new domain endings, search links
carrying hundreds of characters of tracking:

* 68% of the phishing addresses were rated Suspicious or worse, and 79% raised
  at least one finding — from the address alone, before the page was read
* Not one of the 115 legitimate addresses was rated below Probably Safe, and
  97% of them raised nothing at all

Those figures are a floor rather than a ceiling: they come from reading
addresses only, and on a real page the extension has the page in front of it
too. The measurement runs as part of the test suite, so a change that catches
more phishing by also flagging ordinary sites fails the build.

The phishing list was used to test the checks, not wired into them — nothing is
looked up while you browse.

---

## Search terms (up to 7)

phishing detector, scam website checker, site safety rating, url checker,
anti-phishing, website security scanner, link safety

---

## Permission justifications

Partner Center asks why each permission is needed. Keep these short and exact.

- **Read and change all your data on all websites** (`host_permissions`
  `http://*/*`, `https://*/*`): the extension rates the page you are looking
  at, so it has to be able to read the page you are looking at. It reads the
  document, never writes to it, and adds only its own button inside a shadow
  root so the page's own layout is untouched.
- **storage**: remembers where you dragged the button, whether it is
  minimised, and the last rating per tab. All of it is local to the browser.
- **activeTab**: lets the toolbar popup show the rating for the tab you are
  on when you click the icon.

## Privacy answers

- Does this extension collect personal data? **No.**
- Does it transmit data off the device? **No.** It makes no network requests.
- Privacy policy: state that all analysis happens locally and nothing is
  collected, stored remotely, or shared.

## If a reviewer asks about the measurement

The corpus is in the repository under `test/corpus/`, the script that produces
the figures is `tools/corpus-check.js`, and it runs on every `npm test`. The
phishing addresses came from OpenPhish's public feed and are used only as test
data — the extension performs no lookups of any kind at runtime.
