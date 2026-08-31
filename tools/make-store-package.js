/*
 * make-store-package.js -- builds the .zip that goes to the Edge / Chrome
 * extension store.
 *
 * The store package is not the repository folder. Two differences matter:
 *
 *   - manifest.json has to sit at the ROOT of the zip. Zipping the folder
 *     itself puts it one level down, which the store rejects.
 *   - only the files the extension actually loads belong in it. A second
 *     manifest (the Firefox variant) and the documentation are noise at best
 *     and a review question at worst.
 *
 * It also checks the manifest against the store's limits before packing, so a
 * package that would fail validation never gets built.
 *
 *   npm run store-package [-- --firefox]
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SOURCE = path.join(ROOT, 'extension');
const forFirefox = process.argv.includes('--firefox');

/* What the stores enforce. Exceeding any of these fails validation on upload
   rather than in review, which is what makes them worth checking here. */
const LIMITS = {name: 45, description: 132, short_name: 12, version: 20};

function fail(message) {
    console.error('store-package: ' + message);
    process.exit(1);
}

const manifestName = forFirefox ? 'manifest.firefox.json' : 'manifest.json';
const manifest = JSON.parse(fs.readFileSync(path.join(SOURCE, manifestName), 'utf8'));

Object.keys(LIMITS).forEach(function (field) {
    const value = manifest[field];
    if (typeof value === 'string' && value.length > LIMITS[field]) {
        fail(`${field} is ${value.length} characters, the store allows ${LIMITS[field]}:\n  "${value}"`);
    }
});
if (manifest.manifest_version !== 3) { fail('manifest_version must be 3'); }
if (!/^\d+(\.\d+){0,3}$/.test(manifest.version)) { fail('version must be up to four dot-separated numbers'); }

/* Every file the manifest points at, and nothing else. */
const files = new Set(['manifest.json']);
const add = (file) => { if (file) { files.add(file.replace(/^\//, '')); } };

Object.values(manifest.icons || {}).forEach(add);
Object.values((manifest.action && manifest.action.default_icon) || {}).forEach(add);
add(manifest.action && manifest.action.default_popup);
(manifest.content_scripts || []).forEach((entry) => {
    (entry.js || []).forEach(add);
    (entry.css || []).forEach(add);
});
if (manifest.background) {
    add(manifest.background.service_worker);
    (manifest.background.scripts || []).forEach(add);
}
(manifest.web_accessible_resources || []).forEach((entry) => (entry.resources || []).forEach(add));

/* The popup is HTML, so whatever it links to has to come too. */
if (manifest.action && manifest.action.default_popup) {
    const html = fs.readFileSync(path.join(SOURCE, manifest.action.default_popup), 'utf8');
    const linked = html.match(/(?:src|href)="([^"]+)"/g) || [];
    linked.map((m) => m.replace(/^(?:src|href)="/, '').replace(/"$/, ''))
        .filter((f) => !/^(https?:|data:|#)/.test(f))
        .forEach(add);
}

const missing = [...files].filter((file) => !fs.existsSync(path.join(SOURCE, file)));
if (missing.length) { fail('the manifest points at files that are not there: ' + missing.join(', ')); }

const out = path.join(ROOT, 'dist');
const stage = path.join(out, 'package');
fs.rmSync(stage, {recursive: true, force: true});
fs.mkdirSync(stage, {recursive: true});

[...files].forEach((file) => {
    const from = path.join(SOURCE, file === 'manifest.json' ? manifestName : file);
    const to = path.join(stage, file);
    fs.mkdirSync(path.dirname(to), {recursive: true});
    fs.copyFileSync(from, to);
});

const zipName = `VeriSite-${manifest.version}${forFirefox ? '-firefox' : ''}.zip`;
const zipPath = path.join(out, zipName);
fs.rmSync(zipPath, {force: true});
execFileSync('zip', ['-rq', zipPath, '.'], {cwd: stage});
fs.rmSync(stage, {recursive: true, force: true});

console.log(`${zipName}  (${(fs.statSync(zipPath).size / 1024).toFixed(0)} KB)`);
console.log('  manifest.json is at the root, as the store requires');
console.log('  ' + [...files].length + ' files: ' + [...files].sort().join(', '));
console.log('  description: ' + manifest.description.length + '/' + LIMITS.description + ' characters');
console.log('  permissions: ' + (manifest.permissions || []).join(', '));
