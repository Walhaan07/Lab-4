/*
 * corpus.test.js -- measures the analyser against labelled sets of addresses.
 *
 * Individual tests say "this address should be caught". This one asks the
 * question that actually matters: across a few hundred real phishing
 * addresses and a few hundred legitimate ones, how many does it get right,
 * and does a change that catches more also start catching the wrong things?
 *
 * The thresholds are floors, not targets. They are set a little below what
 * the analyser currently manages, so ordinary improvement never fails the
 * build but a regression does.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const SpamAnalyzer = require('../extension/js/spam-analyzer.js');

function load(name) {
    return fs.readFileSync(path.join(__dirname, 'corpus', name), 'utf8')
        .split('\n').map((line) => line.trim())
        .filter((line) => line && line.charAt(0) !== '#');
}

/* Address-only scans: nothing here is fetched, and nothing in the phishing
   list is ever visited. In the browser the extension also has the page, so
   these numbers are the floor rather than the ceiling. */
const phishing = load('phishing.txt').map((url) => ({url, report: SpamAnalyzer.analyze(url)}));
const benign = load('benign.txt').map((url) => ({url, report: SpamAnalyzer.analyze(url)}));

test('the phishing corpus is mostly caught from the address alone', () => {
    const caught = phishing.filter((row) => row.report.score < 60);
    const share = caught.length / phishing.length;
    assert.ok(share >= 0.62,
        `caught ${caught.length}/${phishing.length} (${(share * 100).toFixed(1)}%), expected at least 62%`);
});

test('most of the phishing corpus raises something', () => {
    const flagged = phishing.filter((row) => row.report.failed.length > 0);
    const share = flagged.length / phishing.length;
    assert.ok(share >= 0.75,
        `flagged ${flagged.length}/${phishing.length} (${(share * 100).toFixed(1)}%), expected at least 75%`);
});

test('no legitimate address is called suspicious', () => {
    /* The one that matters most. A scanner that cries wolf gets switched off,
       and then it catches nothing at all. */
    const wrong = benign.filter((row) => row.report.score < 75);
    assert.deepStrictEqual(wrong.map((row) => `${row.report.score} ${row.url}`), [],
        'legitimate addresses were rated below the safe bands');
});

test('legitimate addresses are almost all left completely alone', () => {
    const clean = benign.filter((row) => row.report.score === 100);
    const share = clean.length / benign.length;
    assert.ok(share >= 0.92,
        `${clean.length}/${benign.length} (${(share * 100).toFixed(1)}%) scored 100, expected at least 92%`);
});

test('the corpora are what they claim to be', () => {
    // A corpus that quietly empties would pass every threshold above.
    assert.ok(phishing.length >= 200, `only ${phishing.length} phishing addresses`);
    assert.ok(benign.length >= 90, `only ${benign.length} legitimate addresses`);
    phishing.concat(benign).forEach((row) => {
        assert.ok(!row.report.error, `${row.url} could not be parsed: ${row.report.error}`);
    });
});
