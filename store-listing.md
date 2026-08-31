# Store listing copy — VeriSite 5.0.0

Paste these into Partner Center → Store listings. Every number here is checked
against what the extension actually does (`npm run corpus`, `npm test`). If
the behaviour changes, change this too.

---

## Short description (132 character limit)

Shows the URL of every page you visit and rates it for phishing, pharming and scam risk. 100 checks, all in your browser.

---

## Description

VeriSite puts a small button on every page you visit. It shows the address you are really on, and rates the site out of 100 with a grade from A to F. Press it and the full report opens: every check that ran, what each one looks for, and what it found — in plain English, not jargon.

HOW WELL DOES IT WORK?

That is the only question worth asking of a tool like this, so it is measured rather than claimed. Against 234 live phishing addresses published by OpenPhish, and 99 ordinary ones chosen to look like them — real projects on the same free hosting, real shops on the same new domain endings, search links carrying 450 characters of tracking:

• 69% of the phishing addresses were rated Suspicious or worse, and 79% raised at least one finding — from the address alone, before the page was even read
• Not one of the 99 legitimate addresses was rated below Probably Safe, and 97% of them raised nothing at all

Those figures are a floor rather than a ceiling: they come from reading addresses only, and on a real page the extension has the page in front of it too. The measurement runs as part of the test suite, so a change that catches more phishing by also flagging ordinary sites fails the build.

To be clear about what that means: nothing is looked up while you browse. The phishing list was used to test the checks, not wired into them.

WHAT IT LOOKS FOR

100 independent checks, in three layers.

• Reputation — addresses that give themselves away, including the published anti-phishing test pages that a working filter is expected to stop you reaching.
• Heuristics — 37 checks on the address, and 63 on the page itself: the connection, the forms, the wording and the scripts.
• Patterns — nine combinations that no single check can see on its own. A password box is ordinary. A password box on a throwaway sub-domain wearing a bank's logo is a phishing kit.

Among the things it recognises:

• Look-alike names — paypa1.com, robiox for roblox, faceb00k with zeros, lnstagram with an l, or a name spelled in Cyrillic that reads as apple.com. Every part of the address is read, not just the domain, because that is where these names hide: the site in faicbok.vercel.app is "faicbok", and nothing is wrong with vercel.app.
• Credential harvesting — cloned sign-in pages, forms that post to a chat bot or an e-mail address, pages collecting a one-time code alongside your password
• Pharming — pages working on your router's settings, or pointing at machines inside your own network
• Crypto wallet drainers — recovery-phrase requests, and approvals dressed up as payments
• Fake CAPTCHAs that talk you into running a command yourself
• Tech-support scares, fake update prompts, prize and giveaway scams, gift-card payment demands
• Malware delivery — a .pdf.exe wearing a document's icon, installers pushed from somewhere other than the site offering them
• Throwaway addresses — a bank's name on hosting anyone can claim in a minute, a generated name that means nothing, a path made only of identifiers

IT KNOWS WHOSE WORDS THEY ARE

Ask an assistant about scams, or search for one, and the page fills with scam vocabulary the site itself never said. VeriSite separates what a site claims from what its visitors typed: 22 of the wording checks stand down on assistants, search results, inboxes and forums, and the report tells you when they did. A page that says those things in its own copy is still caught.

The same care goes the other way. A company's own project page on a platform it does not own, an exchange warning you never to share your recovery phrase, an article explaining how an attack works with the code printed in it — none of these is the thing it resembles, and each one has a test of its own saying so.

EVERYTHING STAYS IN YOUR BROWSER

No account. No tracking. No uploads. The extension makes no network requests at all — there is no fetch, no XMLHttpRequest and no remote code anywhere in it. Every check runs against the page already open in front of you, which is why the report says "runs in this browser".

It asks for access to the sites you visit for one reason: it cannot rate a page it is not allowed to read.

THE BUTTON STAYS OUT OF THE WAY

Drag it anywhere; it remembers where you put it and moves itself clear of a site's own bottom bar. Park it against the left edge and the whole thing mirrors — the minimise control travels round the pill and it opens the other way, so it never opens off the screen. Collapse it to a circle showing just the grade, open the report with Alt+Shift+S, or switch the button off entirely and use the toolbar icon instead. Light and dark themes follow your system setting.

WHAT IT IS NOT

VeriSite is a second opinion, not a replacement for the protection built into your browser. It has no live blocklist, so a site registered this morning is judged on how it is built rather than on what is known about it. Roughly a third of the phishing addresses it was measured against were not caught from the address alone, and it will sometimes be wrong the other way too. Leave Microsoft Defender SmartScreen switched on.

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
