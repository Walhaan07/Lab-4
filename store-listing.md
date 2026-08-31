# Store listing copy — VeriSite 5.0.0

Paste these into Partner Center → Store listings. Everything here is checked
against what the extension actually does; if the behaviour changes, change
this too.

---

## Short description (132 character limit)

Shows the URL of every page you visit and rates it for phishing, pharming and scam risk. 100 checks, all in your browser.

---

## Description

VeriSite puts a small button on every page you visit. It shows the address you are really on, and rates the site out of 100 with a grade from A to F. Press it and the full report opens: every check that ran, what each one looks for, and what it found — in plain English, not jargon.

WHAT IT LOOKS FOR

100 independent checks, in three layers.

• Reputation — addresses that are already known, including the published anti-phishing feature test pages that a working filter is expected to stop you reaching.
• Heuristics — the address, the connection, the forms, the wording and the scripts.
• Patterns — combinations that no single check can see on its own. A password box is ordinary. A password box on a throwaway sub-domain wearing a bank's logo is a phishing kit.

Among the things it recognises:

• Look-alike names — paypa1.com, robiox instead of roblox, faceb00k with zeros, or a name spelled in Cyrillic letters that reads as apple.com. Every part of the address is read, not just the domain.
• Credential harvesting — cloned sign-in pages, forms that post to a chat bot or an e-mail address, pages collecting a one-time code alongside your password
• Pharming — pages working on your router's settings, or pointing at machines inside your own network
• Crypto wallet drainers — recovery-phrase requests, and approvals dressed up as payments
• Fake CAPTCHAs that talk you into running a command yourself
• Tech-support scares, fake update prompts, prize and giveaway scams, gift-card payment demands
• Malware delivery — a .pdf.exe wearing a document's icon, installers pushed from somewhere other than the site offering them
• Pages built to be hard to examine — packed code, visitor cloaking, blocked developer tools
• Throwaway addresses — a bank's name on free hosting anyone can claim in a minute, a generated name with no meaning, a path made only of identifiers

IT KNOWS WHOSE WORDS THEY ARE

Ask an assistant about scams, or search for one, and the page fills with scam vocabulary that the site itself never said. VeriSite separates what a site claims from what its visitors typed: the wording checks stand down on assistants, search results, inboxes and forums, and the report tells you when they did. A page that says those things in its own copy is still caught.

EVERYTHING STAYS IN YOUR BROWSER

No account. No tracking. No uploads. The extension makes no network requests at all — there is no fetch, no XMLHttpRequest and no remote code anywhere in it. Every check runs against the page already open in front of you, which is why the report says "runs in this browser".

It asks for access to the sites you visit for one reason: it cannot rate a page it is not allowed to read.

THE BUTTON STAYS OUT OF THE WAY

Drag it anywhere; it remembers where you put it and moves itself clear of a site's own bottom bar. Minimise it to a circle showing just the grade, open the report with Alt+Shift+S, or switch the button off entirely and use the toolbar icon instead. Light and dark themes follow your system setting.

WHAT IT IS NOT

Measured against 234 live phishing addresses published by OpenPhish, VeriSite rates around two thirds of them Suspicious or worse from the address alone, before the page is even read — while leaving every one of a matched set of ordinary sites in the safe bands. The address is only half of what it looks at, so on a real page it has more to go on.

VeriSite is a second opinion, not a replacement for the protection built into your browser. It has no live blocklist, so a site registered this morning is judged on how it is built rather than on what is known about it, and it can be wrong in both directions. Leave Microsoft Defender SmartScreen switched on.

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
