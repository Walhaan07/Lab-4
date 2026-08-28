/*
 * sync-shared.js -- copies the single source of truth (src/spam-analyzer.js)
 * into the two places that need to load it at runtime:
 *
 *   extension/js/spam-analyzer.js   loaded by the content script
 *   public_html/js/spam-analyzer.js loaded by the NetBeans demo page
 *
 * Run with:  npm run sync
 * Always edit src/spam-analyzer.js, never the copies.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const source = path.join(root, 'src', 'spam-analyzer.js');
const targets = [
    path.join(root, 'extension', 'js', 'spam-analyzer.js'),
    path.join(root, 'public_html', 'js', 'spam-analyzer.js')
];

const banner = [
    '/* ------------------------------------------------------------------',
    ' * GENERATED FILE - do not edit.',
    ' * Copied from src/spam-analyzer.js by "npm run sync".',
    ' * ------------------------------------------------------------------ */',
    ''
].join('\n');

const code = fs.readFileSync(source, 'utf8');

targets.forEach((target) => {
    fs.mkdirSync(path.dirname(target), {recursive: true});
    fs.writeFileSync(target, banner + code);
    console.log('synced ->', path.relative(root, target));
});
