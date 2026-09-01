/*
 * analyzer.test.js -- unit tests for the spam analyser.
 * Run with:  npm test      (uses the Node.js built-in test runner)
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const SpamAnalyzer = require('../extension/js/spam-analyzer.js');

function idsOf(report) {
    return report.failed.map((check) => check.id);
}

test('a normal HTTPS site scores highly', () => {
    const report = SpamAnalyzer.analyze('https://www.bbc.co.uk/news');
    assert.ok(report.score >= 90, `expected >= 90, got ${report.score}`);
    assert.strictEqual(report.rating, 'A');
    assert.strictEqual(report.isSpam, false);
});

test('a phishing style URL is rated F', () => {
    const report = SpamAnalyzer.analyze('http://paypal.secure-login.verify-account.tk/webscr?cmd=login');
    assert.strictEqual(report.rating, 'F');
    assert.strictEqual(report.isSpam, true);
    const ids = idsOf(report);
    assert.ok(ids.includes('https'), 'should flag missing HTTPS');
    assert.ok(ids.includes('brand-impersonation'), 'should flag the paypal brand');
    assert.ok(ids.includes('suspicious-tld'), 'should flag the .tk domain');
});

test('a raw IP address host is detected', () => {
    const report = SpamAnalyzer.analyze('http://192.168.4.12:8899/login/verify/account');
    assert.ok(idsOf(report).includes('ip-host'));
    assert.ok(idsOf(report).includes('nonstandard-port'));
});

test('punycode and the "@" trick are detected', () => {
    const puny = SpamAnalyzer.analyze('https://xn--80ak6aa92e.com/');
    assert.ok(idsOf(puny).includes('punycode'));

    const at = SpamAnalyzer.analyze('https://www.google.com@malicious.example/login');
    assert.ok(idsOf(at).includes('at-symbol'));
});

test('URL shorteners are flagged', () => {
    assert.ok(idsOf(SpamAnalyzer.analyze('https://bit.ly/3xYzAb')).includes('shortener'));
});

test('a direct executable download is flagged', () => {
    assert.ok(idsOf(SpamAnalyzer.analyze('http://files.example.tk/update.exe')).includes('executable-url'));
});

test('registrable domain handles multi-part public suffixes', () => {
    assert.strictEqual(SpamAnalyzer.registrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
    assert.strictEqual(SpamAnalyzer.registrableDomain('mail.google.com'), 'google.com');
    assert.strictEqual(SpamAnalyzer.registrableDomain('example.com'), 'example.com');
});

test('page-content tests are skipped, not failed, on a URL-only scan', () => {
    const report = SpamAnalyzer.analyze('https://example.com/');
    assert.ok(report.skipped.length > 0, 'DOM tests should be skipped');
    assert.ok(report.failed.every((check) => check.status === 'failed'));
    assert.strictEqual(report.totalTests, report.passed.length + report.failed.length + report.skipped.length);
});

test('an unparsable address is reported instead of throwing', () => {
    const report = SpamAnalyzer.analyze('not a url at all');
    assert.strictEqual(report.score, 0);
    assert.ok(report.error);
});

/* ------------------------------------------------- tests added in v1.1 */

test('a typo-squatted brand domain lands in the F band', () => {
    const report = SpamAnalyzer.analyze('https://paypa1.com/login');
    assert.ok(idsOf(report).includes('typosquat-brand'));
    assert.ok(report.score <= 30, `expected a low score, got ${report.score}`);
    assert.strictEqual(report.rating, 'F');
    /* The cap is a floor under the verdict, not the route to it: enough
       findings reach the same place on their own, and then there is nothing
       for the cap to hold down. Either way the page is F. */
    assert.ok(report.scoreCap <= 30, `the cap should still be set, got ${report.scoreCap}`);
});

test('the real brand domain is never flagged as a typo-squat', () => {
    const report = SpamAnalyzer.analyze('https://www.paypal.com/signin');
    assert.strictEqual(report.score, 100);
    assert.deepStrictEqual(idsOf(report), []);
});

test('a domain ending hidden in the sub-domain is detected', () => {
    const ids = idsOf(SpamAnalyzer.analyze('https://paypal.com.secure-verify.tk/login'));
    assert.ok(ids.includes('tld-in-subdomain'));
    assert.ok(ids.includes('brand-impersonation'));
});

test('a mixed-alphabet host is detected as a homograph', () => {
    // "paypal" with a Cyrillic "а"
    const report = SpamAnalyzer.analyze('https://p\u0430ypal.com/');
    assert.ok(idsOf(report).includes('mixed-scripts'));
    assert.strictEqual(report.rating, 'F');
});

test('an open redirect parameter is detected', () => {
    const ids = idsOf(SpamAnalyzer.analyze('https://example.com/go?url=https://evil.example.tk/x'));
    assert.ok(ids.includes('redirect-param'));
});

test('a machine generated domain is detected, a readable one is not', () => {
    assert.ok(idsOf(SpamAnalyzer.analyze('https://xkqzrtvbnmwq.com/')).includes('random-domain'));
    assert.ok(!idsOf(SpamAnalyzer.analyze('https://riverside-library.com/')).includes('random-domain'));
});

test('an ordinary page mentioning a brand is not flagged', () => {
    // The brand test must not fire on /blog/how-to-use-google-analytics.
    const report = SpamAnalyzer.analyze('https://blog.example.com/how-to-use-google-analytics');
    assert.strictEqual(report.score, 100);
});

test('non web schemes are reported', () => {
    const ids = idsOf(SpamAnalyzer.analyze('ftp://files.example.com/pub/x'));
    assert.ok(ids.includes('unsafe-scheme'));
});

test('every check explains itself in a few plain-English sentences', () => {
    SpamAnalyzer.checks.forEach((check) => {
        assert.ok(check.about, `${check.id} has no explanation`);
        assert.ok(check.about.length >= 120,
            `${check.id}'s explanation is too short (${check.about.length} chars)`);
        assert.ok(check.about.length <= 420,
            `${check.id}'s explanation is too long (${check.about.length} chars)`);
        assert.ok(/[.!?]$/.test(check.about.trim()), `${check.id}'s explanation is not a sentence`);
    });
});

test('the explanation is carried into the report', () => {
    const report = SpamAnalyzer.analyze('http://paypal.secure-login.verify-account.tk/webscr');
    assert.ok(report.failed.every((check) => typeof check.about === 'string' && check.about.length > 0));
    assert.ok(report.passed.every((check) => typeof check.about === 'string' && check.about.length > 0));
});

test('every check has a unique id, a fail title and a positive weight', () => {
    const ids = SpamAnalyzer.checks.map((check) => check.id);
    assert.strictEqual(new Set(ids).size, ids.length, 'duplicate check id');
    SpamAnalyzer.checks.forEach((check) => {
        assert.ok(check.failTitle, `${check.id} has no failTitle`);
        assert.ok(check.title, `${check.id} has no title`);
        assert.ok(check.weight > 0, `${check.id} has no weight`);
        assert.strictEqual(typeof check.run, 'function');
        if (check.cap !== undefined) {
            assert.ok(check.cap >= 0 && check.cap <= 100, `${check.id} has a silly cap`);
        }
    });
});

test('the report bookkeeping always adds up', () => {
    const report = SpamAnalyzer.analyze('http://192.168.1.1/login');
    assert.strictEqual(
        report.passed.length + report.failed.length + report.skipped.length,
        report.totalTests
    );
    assert.strictEqual(report.totalTests, SpamAnalyzer.checks.length);
    assert.ok(report.penalty <= report.maxPenalty);
});

test('failed checks are sorted by severity, worst first', () => {
    const report = SpamAnalyzer.analyze('http://paypal.secure-login.verify-account.tk/webscr?cmd=login');
    const points = report.failed.map((check) => check.points);
    assert.deepStrictEqual(points, [...points].sort((a, b) => b - a));
});

test('odd inputs never throw', () => {
    const inputs = ['', null, undefined, 'http://', 'https://.', 'javascript:alert(1)',
                    'data:text/html,<h1>hi</h1>', 'http://[::1]:8080/', 'HTTPS://EXAMPLE.COM/'];
    inputs.forEach((input) => {
        const report = SpamAnalyzer.analyze(input);
        assert.ok(typeof report.score === 'number' && report.score >= 0 && report.score <= 100,
            `bad score for input ${JSON.stringify(input)}`);
    });
});

test('score always stays within 0..100', () => {
    const urls = [
        'https://example.com/',
        'http://a-b-c-d-e.free-gift-cards-winner1234.xn--80ak6aa92e.tk/login/verify/secure/account/update/confirm/password/billing.exe?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=%41%42%43%44%45%46'
    ];
    urls.forEach((url) => {
        const report = SpamAnalyzer.analyze(url);
        assert.ok(report.score >= 0 && report.score <= 100, `score out of range for ${url}`);
    });
});

/* ------------------------------------------------- robustness (v3) */

test('a document that cannot be read is treated as a scan without one', () => {
    // Detached, torn down mid-navigation, or simply hostile: reading the page
    // must never take the whole scan with it.
    const hostile = {
        get title() { throw new Error('no'); },
        get body() { throw new Error('no'); },
        querySelector() { throw new Error('no'); },
        querySelectorAll() { throw new Error('no'); }
    };
    const report = SpamAnalyzer.analyze({url: 'https://example.com/', document: hostile});
    assert.strictEqual(report.score, 100);
    assert.ok(report.skipped.length > 0, 'the page tests should be skipped');

    // and the address tests still do their work
    const bad = SpamAnalyzer.analyze({url: 'https://paypal-verify-account.tk/login', document: hostile});
    assert.strictEqual(bad.rating, 'F');
    assert.ok(bad.failed.map((c) => c.id).includes('brand-in-domain'));
});

test('the same page scanned twice gives the same answer', () => {
    // The analyser keeps no state between runs; a second opinion that differed
    // from the first would mean it does.
    const url = 'https://paypal.com.secure-verify.tk/webscr?cmd=login';
    const first = SpamAnalyzer.analyze(url);
    const second = SpamAnalyzer.analyze(url);
    assert.strictEqual(first.score, second.score);
    assert.deepStrictEqual(first.failed.map((c) => c.id), second.failed.map((c) => c.id));
    assert.deepStrictEqual(first.patterns.map((p) => p.id), second.patterns.map((p) => p.id));
});

test('every check reports a category the report can group by', () => {
    const known = ['Transport', 'URL', 'Forms', 'Content', 'Scripts', 'Downloads', 'Reputation', 'Network'];
    SpamAnalyzer.checks.forEach((check) => {
        assert.ok(known.includes(check.category), `${check.id} has category "${check.category}"`);
    });
});

test('no check silently fails to run', () => {
    /*
     * Every test is wrapped in a guard, so a bug inside one turns it into a
     * "skipped" line instead of an exception - which is right at runtime and
     * dangerous in development, because detection quietly weakens and the
     * summary still looks healthy. A skip may only ever be for the two
     * reasons the analyser itself gives.
     */
    const urls = ['https://www.bbc.co.uk/news', 'https://yenkpaaqhhgtkhe.workers.dev/',
                  'http://paypal.secure-login.verify-account.tk/webscr?cmd=login',
                  'https://xn--80ak6aa92e.com/', 'http://[::1]:8080/', 'https://192.168.1.1/setup'];
    urls.forEach((url) => {
        SpamAnalyzer.analyze(url).skipped.forEach((check) => {
            assert.ok(/Needs the page content|time budget|words on screen are written/.test(check.detail),
                `${check.id} did not run on ${url}: ${check.detail}`);
        });
    });
});

/* ------------------------------- names that only resemble a brand (v5.1) */

test('an ordinary word in a sub-domain is not a misspelled brand', () => {
    /*
     * Edit distance cannot tell a typosquat from a word that happens to sit
     * one letter from a brand, and a great many do: "mail" is one from gmail,
     * "case" from chase, "stream" from steam, "finance" from binance. Every
     * company's webmail host was being rated F for it.
     */
    ['https://mail.example-corp.co.uk/', 'https://stream.example-corp.com/',
     'https://finance.example-corp.com/', 'https://case.example-corp.com/',
     'https://email.example-corp.com/'].forEach((url) => {
        const report = SpamAnalyzer.analyze(url);
        assert.ok(!report.failed.some((c) => c.id === 'brand-in-domain'),
            `${url} was read as impersonating a brand`);
        assert.strictEqual(report.rating, 'A', `${url} rated ${report.rating}`);
    });
});

test('a resemblance with nothing behind it cannot condemn a domain on its own', () => {
    // "telegraph" is two letters from "telegram". Worth a note, never a verdict.
    const report = SpamAnalyzer.analyze('https://www.example-telegraph.co.uk/');
    assert.ok(['A', 'B'].includes(report.rating),
        `rated ${report.rating}: ${report.failed.map((c) => c.id).join(', ')}`);
});

test('a misspelling with a phishing name around it still counts', () => {
    ['https://facbookapp.vercel.app/', 'https://trust-wallaet-io.pages.dev/',
     'https://exooduseb3wallet.gitbook.io/'].forEach((url) => {
        const report = SpamAnalyzer.analyze(url);
        assert.ok(report.failed.some((c) => c.id === 'brand-in-domain'),
            `${url} was not reported`);
        assert.ok(report.score < 60, `${url} scored ${report.score}`);
    });
});

test('a brand spelled across a dot is still that brand', () => {
    // "s.team-zi.com" reads as steam; no single label ever holds the word,
    // which is the whole point of splitting it that way.
    const report = SpamAnalyzer.analyze('https://s.team-zi.com/');
    assert.ok(report.failed.some((c) => c.id === 'brand-in-domain'),
        'a brand spelled across a dot went unreported');
    assert.ok(report.score < 60, `scored ${report.score}`);
});

test('one company\'s own brands do not impersonate each other', () => {
    // Outlook, Office 365 and Microsoft are one company; so are Apple and
    // iCloud. Each brand's domain list is written separately and none can be
    // complete, so ownership is settled across the lists rather than within one.
    ['https://outlook.office365.com/', 'https://outlook.live.com/mail/',
     'https://photos.icloud.com/', 'https://music.apple.com/',
     'https://login.microsoftonline.com/', 'https://pay.google.com/'].forEach((url) => {
        const report = SpamAnalyzer.analyze(url);
        assert.strictEqual(report.rating, 'A',
            `${url} rated ${report.rating}: ${report.failed.map((c) => c.id).join(', ')}`);
    });

    // A brand on a domain its company does not own is still the classic shape.
    ['https://outlook.evil.tk/', 'https://paypal.secure-verify.tk/',
     'https://apple.icloud-verify.cf/'].forEach((url) => {
        assert.ok(SpamAnalyzer.analyze(url).score < 40, `${url} was not caught`);
    });
});

test('an ordinary account path is not a phishing kit', () => {
    /*
     * "Two sign-in words in a path" is the shape of nearly every real account
     * area on the web. Measured against the phishing corpus it identified
     * none of them, while reporting Instagram, Okta, Dropbox and any bank
     * with a two-step sign-in.
     */
    ['https://www.instagram.com/accounts/login/',
     'https://acme.okta.com/login/login.htm',
     'https://www.dropbox.com/account/security/password/update',
     'https://www.example-bank.co.uk/securelogin/verify-account',
     'https://accounts.example.com/signin/verify'].forEach((url) => {
        assert.ok(!SpamAnalyzer.analyze(url).failed.some((c) => c.id === 'kit-path'),
            `${url} was read as a phishing kit`);
    });
});

test('a sign-in path handled by a dropped script still is one', () => {
    // What a kit has and a routed application does not: its own script at the
    // end of the sign-in path.
    ['https://example.tk/login/verify/next.php',
     'https://example.tk/secure/account/update.php',
     'https://example.tk/account/login/submit.php'].forEach((url) => {
        assert.ok(SpamAnalyzer.analyze(url).failed.some((c) => c.id === 'kit-path'),
            `${url} was not reported`);
    });
});

test('a long, heavily parameterised address is never a threat by itself', () => {
    /*
     * Search, ad-click and analytics links are all long and full of
     * parameters. Those findings may cost a page a few points, but they must
     * not be able to move it out of the safe band.
     */
    const url = 'https://www.google.com/search?q=claude&oq=claude+&gs_lcrp=' + 'EgRlZGdlKgYIABBFGDkyBggAEEUYOTIJCAEQABgNGIAE'.repeat(4) +
        '&sourceid=chrome&source=chrome.ob&ie=UTF-8';
    const report = SpamAnalyzer.analyze(url);
    assert.strictEqual(report.threatPenalty, 0,
        `threat findings: ${report.failed.map((c) => c.id).join(', ')}`);
    assert.ok(['A', 'B'].includes(report.rating), `rated ${report.rating}`);
});
