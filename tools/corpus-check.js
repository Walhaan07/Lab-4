/*
 * corpus-check.js -- measures the analyser against labelled sets of addresses.
 *
 *   npm run corpus            summary
 *   npm run corpus -- --miss  and every address that was missed
 *   npm run corpus -- --fp    and every legitimate address that was flagged
 *
 * These are address-only scans: no page is fetched, and nothing in the
 * phishing list is ever visited. In the browser the extension also has the
 * page itself, so what this measures is the floor rather than the ceiling.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const SpamAnalyzer = require('../extension/js/spam-analyzer.js');

function load(name) {
    return fs.readFileSync(path.join(__dirname, '..', 'test', 'corpus', name), 'utf8')
        .split('\n').map((line) => line.trim())
        .filter((line) => line && line.charAt(0) !== '#');
}

function score(urls) {
    return urls.map((url) => {
        const report = SpamAnalyzer.analyze(url);
        return {url, score: report.score, rating: report.rating, blocked: report.blocked,
                ids: report.failed.map((c) => c.id)};
    });
}

const phishing = score(load('phishing.txt'));
const benign = score(load('benign.txt'));

const band = (r) => (r.score < 40 ? 'F' : r.score < 60 ? 'D' : r.score < 75 ? 'C' : r.score < 90 ? 'B' : 'A');
const count = (rows, want) => rows.filter((r) => want.includes(band(r))).length;
const pct = (n, total) => ((n / total) * 100).toFixed(1) + '%';

console.log(`\nPHISHING  (${phishing.length} addresses from OpenPhish, address-only scan)`);
['F', 'D', 'C', 'B', 'A'].forEach((b) => {
    const n = phishing.filter((r) => band(r) === b).length;
    console.log(`  ${b}: ${String(n).padStart(3)}  ${pct(n, phishing.length).padStart(6)}  ${'#'.repeat(Math.round(n / 3))}`);
});
console.log(`  caught (F or D): ${count(phishing, ['F', 'D'])}/${phishing.length}  ${pct(count(phishing, ['F', 'D']), phishing.length)}`);
console.log(`  flagged at all : ${count(phishing, ['F', 'D', 'C'])}/${phishing.length}  ${pct(count(phishing, ['F', 'D', 'C']), phishing.length)}`);

console.log(`\nLEGITIMATE  (${benign.length} addresses, including the awkward ones)`);
['A', 'B', 'C', 'D', 'F'].forEach((b) => {
    const n = benign.filter((r) => band(r) === b).length;
    console.log(`  ${b}: ${String(n).padStart(3)}  ${pct(n, benign.length).padStart(6)}  ${'#'.repeat(Math.round(n / 3))}`);
});
const falsePositives = benign.filter((r) => band(r) === 'C' || band(r) === 'D' || band(r) === 'F');
console.log(`  false positives (below B): ${falsePositives.length}`);

if (process.argv.includes('--miss')) {
    console.log('\nMISSED (rated A or B):');
    phishing.filter((r) => band(r) === 'A' || band(r) === 'B')
        .sort((a, b) => b.score - a.score)
        .forEach((r) => console.log(`  ${String(r.score).padStart(3)} ${band(r)}  ${r.url.slice(0, 96)}\n        ${r.ids.join(', ') || 'nothing found'}`));
}
if (process.argv.includes('--fp')) {
    console.log('\nLEGITIMATE ADDRESSES THAT LOST POINTS:');
    benign.filter((r) => r.score < 90).sort((a, b) => a.score - b.score)
        .forEach((r) => console.log(`  ${String(r.score).padStart(3)} ${band(r)}  ${r.url.slice(0, 90)}\n        ${r.ids.join(', ')}`));
}
