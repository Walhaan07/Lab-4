/*
 * ui-check.js -- drives the injected interface in a real browser and checks
 * that every part of it stays inside the window.
 *
 * The geometry is the one thing the unit tests cannot see: jsdom has no
 * layout, so "does the report open off the side of the screen?" can only be
 * answered by a browser. This script parks the button in each corner, opens
 * and closes it, and fails if anything ends up outside the viewport.
 *
 *   npm run ui-check
 *
 * Playwright is an optional dependency; without it the script says so and
 * exits cleanly rather than failing the build.
 */
'use strict';

const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

let chromium = null;
try {
    chromium = require('playwright').chromium;
} catch (e) {
    console.log('ui-check: playwright is not installed - skipping.');
    console.log('          npm install --no-save playwright   enables it.');
    process.exit(0);
}

/* The extension's own files, loaded into a plain page in the same order the
   manifest loads them. Everything that needs the chrome APIs is already
   guarded, so the interface runs unchanged outside an extension. */
const FILES = ['panel-style.js', 'threat-intel.js', 'spam-analyzer.js', 'content.js'];

function buildHarness() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'verisite-ui-'));
    FILES.forEach((file) => {
        fs.copyFileSync(path.join(__dirname, '..', 'extension', 'js', file), path.join(dir, file));
    });
    fs.writeFileSync(path.join(dir, 'harness.html'),
        `<!doctype html><html><head><meta charset="utf-8"><title>UI harness</title>
<style>body{margin:0;font:16px/1.6 system-ui;background:#0e1116;color:#dfe6f2}.pad{padding:40px}</style>
</head><body><div class="pad"><h1>UI harness</h1><p>A plain page for driving the injected interface.</p>
<p><a href="/contact">Contact</a> · <a href="/privacy">Privacy</a></p></div>
${FILES.map((f) => `<script src="./${f}"></script>`).join('\n')}
</body></html>`);
    return path.join(dir, 'harness.html');
}

const READ_BOXES = () => {
    const host = document.getElementById('site-safety-checker-root');
    if (!host || !host.shadowRoot) { return null; }
    const root = host.shadowRoot;
    const box = (el) => {
        if (!el) { return null; }
        const r = el.getBoundingClientRect();
        return {left: Math.round(r.left), right: Math.round(r.right),
                top: Math.round(r.top), bottom: Math.round(r.bottom), width: Math.round(r.width)};
    };
    const panel = root.querySelector('.ssc-panel');
    return {
        dock: box(root.querySelector('.ssc-dock')),
        toggle: box(root.querySelector('.ssc-dock__toggle')),
        button: box(root.querySelector('.ssc-button')),
        panel: panel && !panel.hidden ? box(panel) : null,
        side: root.querySelector('.ssc-dock').classList.contains('ssc-dock--left') ? 'left' : 'right',
        /* What the dock would measure with the whole address showing - the
           width the opening side has to have room for. */
        natural: (function () {
            const button = root.querySelector('.ssc-button');
            const limit = button.style.maxWidth;
            const mini = button.classList.contains('ssc-button--mini');
            button.classList.add('ssc-measuring');
            button.classList.remove('ssc-button--mini');
            button.style.maxWidth = '460px';
            const w = button.getBoundingClientRect().width;
            button.classList.toggle('ssc-button--mini', mini);
            button.style.maxWidth = limit;
            button.classList.remove('ssc-measuring');
            return Math.round(w + root.querySelector('.ssc-dock__toggle').offsetWidth + 7);
        }()),
        width: window.innerWidth,
        height: window.innerHeight
    };
};

(async function main() {
    const harness = buildHarness();
    const browser = await chromium.launch(
        process.env.CHROME_PATH ? {executablePath: process.env.CHROME_PATH} : {});
    const page = await browser.newPage({viewport: {width: 1280, height: 800}});

    const problems = [];
    page.on('pageerror', (error) => problems.push('page error: ' + error.message));

    await page.goto('file://' + harness);
    await page.waitForTimeout(1400);

    const shadow = (selector) => page.evaluateHandle(
        (s) => document.getElementById('site-safety-checker-root').shadowRoot.querySelector(s), selector);
    const click = async (selector) => {
        const handle = await shadow(selector);
        await handle.asElement().click();
        await page.waitForTimeout(1250);
    };
    const dragTo = async (x, y) => {
        const boxes = await page.evaluate(READ_BOXES);
        await page.mouse.move((boxes.button.left + boxes.button.right) / 2,
                              (boxes.button.top + boxes.button.bottom) / 2);
        await page.mouse.down();
        await page.mouse.move(x, y, {steps: 22});
        await page.mouse.up();
        await page.waitForTimeout(650);
    };

    /*
     * Drags the pill one step at a time and reports where the dock was after
     * each one, so the caller can check that it went where the pointer did.
     */
    const dragSweep = async (toX, steps) => {
        const boxes = await page.evaluate(READ_BOXES);
        const y = (boxes.button.top + boxes.button.bottom) / 2;
        let x = (boxes.button.left + boxes.button.right) / 2;
        const step = (toX - x) / steps;
        await page.mouse.move(x, y);
        await page.mouse.down();
        const trail = [];
        for (let i = 0; i < steps; i++) {
            x += step;
            await page.mouse.move(x, y);
            await page.waitForTimeout(20);
            const b = await page.evaluate(READ_BOXES);
            trail.push({pointer: x, left: b.dock.left, right: b.dock.right, side: b.side});
        }
        await page.mouse.up();
        await page.waitForTimeout(700);
        return trail;
    };

    /*
     * The pill is held by whatever part of it was taken hold of, so it may
     * never move further than the pointer did. Turning the dock round used to
     * swap which edge the anchor meant without moving the anchor, which threw
     * the whole thing a pill's width across the window.
     */
    const checkNoJump = (label, trail) => {
        let previous = null;
        trail.forEach((frame) => {
            if (previous) {
                const moved = Math.abs(frame.left - previous.left);
                const asked = Math.abs(frame.pointer - previous.pointer);
                if (moved > asked + 2) {
                    problems.push(`${label}: the dock moved ${Math.round(moved)}px for a ` +
                                  `${Math.round(asked)}px pointer step, at x=${Math.round(frame.pointer)}`);
                }
            }
            previous = frame;
        });
        console.log(`  ${label.padEnd(40)} ${trail.length} steps, ` +
                    `sides: ${[...new Set(trail.map((f) => f.side))].join(' then ')}`);
    };

    /*
     * The toggle turns round when opening the pill there would run it off the
     * edge - not when the circle itself reaches the edge. So by the time the
     * collapsed pill is parked, the side it is on must have room for the whole
     * address.
     */
    const checkOpensInside = async (label) => {
        const b = await page.evaluate(READ_BOXES);
        const room = b.side === 'left' ? b.width - b.dock.left : b.dock.right;
        if (room < b.natural + 8) {
            problems.push(`${label}: parked with ${Math.round(room)}px on the ${b.side} ` +
                          `for a pill that opens to ${Math.round(b.natural)}px`);
        }
        console.log(`  ${label.padEnd(40)} side=${b.side} room=${Math.round(room)} ` +
                    `needs=${Math.round(b.natural)}`);
    };

    const check = async (label) => {
        const b = await page.evaluate(READ_BOXES);
        if (!b) { problems.push(`${label}: the interface did not load`); return; }
        ['dock', 'toggle', 'button', 'panel'].forEach((part) => {
            const r = b[part];
            if (!r) { return; }
            if (r.left < 0 || r.top < 0 || r.right > b.width || r.bottom > b.height) {
                problems.push(`${label}: the ${part} is outside the window ` +
                              `[${r.left},${r.top} - ${r.right},${r.bottom}] in ${b.width}x${b.height}`);
            }
        });
        console.log(`  ${label.padEnd(40)} side=${b.side}` + (b.panel ? '  report open' : ''));
    };

    console.log('Driving the interface:');
    await check('default corner');

    /* The two things the drag has to get right: the pill stays under the
       cursor whichever way the dock turns, and the turn happens while there is
       still room to open rather than once the edge is reached. */
    checkNoJump('dragging the pill to the left edge', await dragSweep(20, 34));
    await check('pill against the left edge');
    checkNoJump('dragging the pill to the right edge', await dragSweep(1260, 40));
    await check('pill against the right edge');

    await click('.ssc-dock__toggle');                 // collapse
    checkNoJump('dragging the circle to the left edge', await dragSweep(20, 34));
    await checkOpensInside('circle against the left edge');
    checkNoJump('dragging the circle to the right edge', await dragSweep(1260, 40));
    await checkOpensInside('circle against the right edge');

    await dragTo(30, 400);                            // left edge
    await check('collapsed against the left edge');
    await click('.ssc-dock__toggle');                 // expand: toggle orbits, pill opens right
    await check('opened against the left edge');
    await click('.ssc-button');
    await check('report open against the left edge');
    await click('.ssc-button');

    for (const [x, y, label] of [[1250, 40, 'top right'], [30, 40, 'top left'],
                                 [640, 780, 'bottom middle'], [30, 770, 'bottom left']]) {
        await dragTo(x, y);
        await click('.ssc-button');
        await check('report open, ' + label);
        await click('.ssc-button');
    }

    for (const [w, h] of [[420, 720], [1100, 420], [360, 640]]) {
        await page.setViewportSize({width: w, height: h});
        await page.waitForTimeout(500);
        await click('.ssc-button');
        await check(`report open in a ${w}x${h} window`);
        await click('.ssc-button');
    }

    await browser.close();
    fs.rmSync(path.dirname(harness), {recursive: true, force: true});

    if (problems.length) {
        console.error('\nui-check failed:\n' + problems.map((p) => '  - ' + p).join('\n'));
        process.exit(1);
    }
    console.log('\nui-check passed: every part stayed inside the window.');
}());
