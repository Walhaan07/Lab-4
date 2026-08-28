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

test('a typo-squatted brand domain is capped into the F band', () => {
    const report = SpamAnalyzer.analyze('https://paypa1.com/login');
    assert.ok(idsOf(report).includes('typosquat-brand'));
    assert.ok(report.score <= 30, `expected the cap to bite, got ${report.score}`);
    assert.strictEqual(report.rating, 'F');
    assert.ok(report.cappedBy.includes('typosquat-brand'));
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
