/*
 * intel.test.js -- the reputation layer and the address tests added in v2.0.
 * Run with:  npm test
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const SpamAnalyzer = require('../extension/js/spam-analyzer.js');
const ThreatIntel = require('../extension/js/threat-intel.js');

function idsOf(report) {
    return report.failed.map((check) => check.id);
}

/* ------------------------------------------------------- reputation layer */

test('the published anti-phishing feature check is recognised by its address', () => {
    // The page the extension missed: ordinary markup, reputable domain, and
    // reachable only when an anti-phishing filter is doing nothing.
    const report = SpamAnalyzer.analyze('https://www.amtso.org/check-desktop-phishing-page/');
    assert.strictEqual(report.blocked, true);
    assert.strictEqual(report.rating, 'F');
    assert.strictEqual(report.verdict, 'Known phishing page');
    assert.ok(report.score <= 10, `expected the block to bite, got ${report.score}`);
    assert.ok(idsOf(report).includes('known-threat'));
    assert.strictEqual(report.threat.kind, 'phishing');
});

test('the other feature checks on the same site are recognised too', () => {
    const cases = [
        ['https://www.amtso.org/check-desktop-download/', 'malware'],
        ['https://www.amtso.org/check-desktop-pua/', 'pua'],
        ['https://www.amtso.org/feature-settings-check-malware-page/', 'malware'],
        ['https://www.amtso.org/check-mobile-phishing-page/', 'phishing']
    ];
    cases.forEach(([url, kind]) => {
        const report = SpamAnalyzer.analyze(url);
        assert.strictEqual(report.blocked, true, `${url} was not blocked`);
        assert.strictEqual(report.threat.kind, kind, `${url} was classed as ${report.threat.kind}`);
    });
});

test('the rest of that site is left alone', () => {
    // Only the test pages are listed; amtso.org itself is an ordinary site.
    const report = SpamAnalyzer.analyze('https://www.amtso.org/about/');
    assert.strictEqual(report.blocked, false);
    assert.strictEqual(report.score, 100);
});

test('the other industry test resources are recognised', () => {
    const urls = [
        'https://testsafebrowsing.appspot.com/s/phishing.html',
        'https://www.itisatrap.org/firefox/its-a-trap.html',
        'https://www.itisatrap.org/firefox/its-an-attack.html',
        'http://www.wicar.org/test-malware.html',
        'https://secure.eicar.org/eicar.com'
    ];
    urls.forEach((url) => {
        assert.strictEqual(SpamAnalyzer.analyze(url).blocked, true, `${url} was not recognised`);
    });
});

test('an administrator can add addresses without editing the code', () => {
    ThreatIntel.clearEntries();
    assert.strictEqual(SpamAnalyzer.analyze('https://intranet-clone.example.com/login').blocked, false);

    SpamAnalyzer.addThreatEntries([
        {match: 'intranet-clone.example.com', kind: 'phishing', label: 'Reported by IT',
         detail: 'Added to the local block list after a reported incident.'}
    ]);
    const report = SpamAnalyzer.analyze('https://intranet-clone.example.com/login');
    assert.strictEqual(report.blocked, true);
    assert.strictEqual(report.threat.source, 'Local block list');
    ThreatIntel.clearEntries();
});

test('a local block list entry can name a path as well as a host', () => {
    ThreatIntel.clearEntries();
    SpamAnalyzer.addThreatEntries(['/payroll-update-2026']);
    assert.strictEqual(SpamAnalyzer.analyze('https://example.com/hr/payroll-update-2026').blocked, true);
    assert.strictEqual(SpamAnalyzer.analyze('https://example.com/hr/holidays').blocked, false);
    ThreatIntel.clearEntries();
});

/* --------------------------------------------------- address level checks */

test('a domain that borrows a brand name is caught even without a sub-domain', () => {
    // The gap that let secure-paypal-billing.com through: the brand is inside
    // the registrable domain, so the sub-domain test never sees it.
    const report = SpamAnalyzer.analyze('https://paypal-billing-support.com/signin');
    assert.ok(idsOf(report).includes('brand-in-domain'));
    assert.ok(report.score <= 30, `expected the cap to bite, got ${report.score}`);
});

test('domains a brand really owns are not mistaken for imitations', () => {
    ['https://s3.eu-west-2.amazonaws.com/bucket/file.txt',
     'https://outlook.live.com/mail/0/',
     'https://www.paypalobjects.com/webstatic/icon/pp32.png',
     'https://www.amazon.co.uk/gp/cart',
     'https://login.microsoftonline.com/common/oauth2/authorize'].forEach((url) => {
        assert.ok(!idsOf(SpamAnalyzer.analyze(url)).includes('brand-in-domain'), `${url} was flagged`);
    });
});

test('a look-alike domain in another alphabet is read back into Latin', () => {
    // "аpple.com" with a Cyrillic "а".
    const report = SpamAnalyzer.analyze('https://аpple.com/signin');
    const ids = idsOf(report);
    assert.ok(ids.includes('homograph-brand') || ids.includes('mixed-scripts'));
    assert.strictEqual(report.rating, 'F');
});

test('a phishing kit path is recognised', () => {
    assert.ok(idsOf(SpamAnalyzer.analyze('https://example.com/wp-content/uploads/2026/login/verify/'))
        .includes('kit-path'));
    assert.ok(idsOf(SpamAnalyzer.analyze('https://example.com/owa/auth/logon.aspx'))
        .includes('kit-path'));
});

test('an ordinary search address is not read as a kit path', () => {
    // A "+"-joined query is not a base64 payload, whatever its length.
    const report = SpamAnalyzer.analyze('https://duckduckgo.com/?q=congratulations+giveaway+scam+free+money');
    assert.ok(!idsOf(report).includes('kit-path'));
    assert.strictEqual(report.score, 100);
});

test('a disguised double extension is caught', () => {
    const report = SpamAnalyzer.analyze('https://files.example.com/invoice.pdf.exe');
    assert.ok(idsOf(report).includes('double-extension'));
    assert.strictEqual(report.rating, 'F');
});

test('a link that already knows your e-mail address is flagged', () => {
    assert.ok(idsOf(SpamAnalyzer.analyze('https://verify.example.com/login?email=someone%40example.com'))
        .includes('credential-in-url'));
    assert.ok(!idsOf(SpamAnalyzer.analyze('https://shop.example.com/search?q=shoes'))
        .includes('credential-in-url'));
});

test('throwaway hosting and dynamic DNS are noticed but never conclusive alone', () => {
    const free = SpamAnalyzer.analyze('https://my-project.pages.dev/');
    assert.ok(idsOf(free).includes('free-subdomain-host'));
    assert.ok(free.score >= 75, `a free host alone must stay in the safe half, got ${free.score}`);

    assert.ok(idsOf(SpamAnalyzer.analyze('https://home.duckdns.org/')).includes('dynamic-dns-host'));
});

/* --------------------------------------------------------- scoring model */

test('the score is measured against a fixed budget, not the size of the suite', () => {
    // Adding tests must sharpen the scanner, never dilute the findings it had.
    const report = SpamAnalyzer.analyze('https://example.com/');
    assert.strictEqual(report.riskBudget, 35);              // address-only scan
    assert.ok(report.maxPenalty > report.riskBudget);
});

test('nuisance findings share a small budget of their own', () => {
    const report = SpamAnalyzer.analyze('https://example.com/');
    assert.strictEqual(report.hygienePenalty, 0);
    assert.ok(SpamAnalyzer.checks.some((check) => check.id === 'ad-density'));
});

test('every pattern names groups of real check ids', () => {
    const ids = new Set(SpamAnalyzer.checks.map((check) => check.id));
    SpamAnalyzer.patterns.forEach((pattern) => {
        assert.ok(pattern.groups.length >= 1, `${pattern.id} has no groups`);
        assert.ok(pattern.need <= pattern.groups.length, `${pattern.id} can never match`);
        pattern.groups.forEach((group) => {
            group.forEach((token) => {
                const id = token.split(':')[0];
                assert.ok(ids.has(id), `pattern ${pattern.id} refers to unknown check "${id}"`);
            });
        });
    });
});

test('a pattern needs separate findings for each of its groups', () => {
    // One look-alike domain sits in two groups; it must not answer for both.
    assert.deepStrictEqual(SpamAnalyzer.matchPatterns(['typosquat-brand']), []);
    const matched = SpamAnalyzer.matchPatterns(['insecure-password-form', 'suspicious-tld', 'brand-impersonation']);
    assert.strictEqual(matched.length, 1);
    assert.strictEqual(matched[0].id, 'credential-kit');
});

test('the analyser and the reputation layer agree on their interface', () => {
    /* The two are separate files loaded separately by the browser. The
       analyser falls back to a stub with this exact shape when the feed is
       missing, so a method added on one side and not the other would break
       that fallback silently. */
    ['lookup', 'matchPageSignature', 'exfilEndpoints', 'kitPaths', 'freeHost',
     'dynamicDns', 'isOfficialDomain', 'addEntries'].forEach((method) => {
        assert.strictEqual(typeof SpamAnalyzer.intel[method], 'function', `intel.${method} is missing`);
    });
    assert.strictEqual(SpamAnalyzer.intel.version, ThreatIntel.version);
});

test('the browser loading path wires the two files together', () => {
    /* Node uses require(); the browser loads both files as content scripts in
       the order the manifest lists them, and they find each other through the
       global object. A manifest that forgot threat-intel.js would still pass
       every other test in this file, so the browser path is exercised here. */
    const vm = require('node:vm');
    const fs = require('node:fs');
    const path = require('node:path');
    const manifest = JSON.parse(fs.readFileSync(
        path.join(__dirname, '..', 'extension', 'manifest.json'), 'utf8'));
    const scripts = manifest.content_scripts[0].js;

    assert.ok(scripts.indexOf('js/threat-intel.js') < scripts.indexOf('js/spam-analyzer.js'),
        'the reputation layer must load before the analyser');

    const sandbox = {URL, TextDecoder, console};      // globals a content script has
    sandbox.self = sandbox;
    vm.createContext(sandbox);
    ['js/threat-intel.js', 'js/spam-analyzer.js'].forEach((file) => {
        vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'extension', file), 'utf8'),
            sandbox, {filename: file});
    });

    assert.ok(sandbox.VeriSiteThreatIntel, 'threat-intel.js did not publish itself');
    assert.ok(sandbox.SpamAnalyzer, 'spam-analyzer.js did not publish itself');
    assert.strictEqual(sandbox.SpamAnalyzer.intel.version, ThreatIntel.version,
        'the analyser did not pick the reputation layer up from the global');

    const report = sandbox.SpamAnalyzer.analyze('https://www.amtso.org/check-desktop-phishing-page/');
    assert.strictEqual(report.blocked, true);
});
