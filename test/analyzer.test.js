/*
 * analyzer.test.js -- unit tests for the spam analyser.
 * Run with:  npm test      (uses the Node.js built-in test runner)
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const SpamAnalyzer = require('../src/spam-analyzer.js');

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
