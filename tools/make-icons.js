/*
 * make-icons.js -- generates VeriSafe's PNG icons with plain Node.js.
 * Run with:  npm run icons
 *
 * Draws the VeriSafe mark - a white shield with a check knocked out of it, on
 * a blue ground - anti-aliased by 4x supersampling, and writes a valid PNG
 * using only the built-in zlib module.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZES = [16, 48, 128];
const OUT_DIR = path.join(__dirname, '..', 'extension', 'icons');
const SS = 4;                                   // supersampling factor

/* ---------------------------------------------------------------- drawing */

/*
 * VeriSafe's mark: a white shield with a check cut out of it, on a blue
 * ground. Drawn analytically and supersampled rather than traced from a
 * bitmap, so it stays crisp at 16px where a scaled-down photo would mush.
 */

/** Half-width of the shield at height v, in unit coordinates. */
function shieldHalfWidth(v) {
    const TOP = 0.185;         // flat top edge
    const SHOULDER = 0.275;    // where the rounded corners finish
    const WAIST = 0.50;        // straight sides down to here
    const TIP = 0.855;         // the point at the bottom
    const HALF = 0.30;

    if (v < TOP || v > TIP) { return 0; }
    if (v < SHOULDER) {                          // rounded upper corners
        const t = (SHOULDER - v) / (SHOULDER - TOP);
        return HALF * Math.sqrt(Math.max(0, 1 - t * t));
    }
    if (v < WAIST) { return HALF; }

    /* Below the waist a single superellipse: the sides stay nearly straight
       for the first stretch and then sweep in to a point. A piecewise taper
       put a visible hip where the two pieces met. */
    const t = (v - WAIST) / (TIP - WAIST);
    return HALF * Math.pow(Math.max(0, 1 - Math.pow(t, 2.2)), 0.55);
}

function distanceToSegment(px, py, ax, ay, bx, by) {
    const dx = bx - ax;
    const dy = by - ay;
    const len2 = dx * dx + dy * dy;
    let t = len2 ? ((px - ax) * dx + (py - ay) * dy) / len2 : 0;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/** Colour of one sample point, in unit coordinates (0..1). */
function sample(u, v) {
    // rounded-square ground with a blue gradient
    const r = 0.22;
    const cx = Math.min(Math.max(u, r), 1 - r);
    const cy = Math.min(Math.max(v, r), 1 - r);
    if (Math.hypot(u - cx, v - cy) > r) { return null; }

    const ground = [
        Math.round(29 + (17 - 29) * v),
        Math.round(111 + (74 - 111) * v),
        Math.round(165 + (122 - 165) * v)
    ];

    const inShield = Math.abs(u - 0.5) <= shieldHalfWidth(v);
    if (!inShield) { return ground; }

    // the check is cut back out of the shield
    const stroke = 0.048;
    const check = Math.min(
        distanceToSegment(u, v, 0.385, 0.495, 0.468, 0.583),
        distanceToSegment(u, v, 0.468, 0.583, 0.632, 0.395)
    );
    if (check <= stroke) { return ground; }

    return [255, 255, 255];
}

function renderRgba(size) {
    const data = Buffer.alloc(size * size * 4);
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            let r = 0, g = 0, b = 0, a = 0;
            for (let sy = 0; sy < SS; sy++) {
                for (let sx = 0; sx < SS; sx++) {
                    const u = (x + (sx + 0.5) / SS) / size;
                    const v = (y + (sy + 0.5) / SS) / size;
                    const c = sample(u, v);
                    if (c) { r += c[0]; g += c[1]; b += c[2]; a += 255; }
                }
            }
            const n = SS * SS;
            const i = (y * size + x) * 4;
            const cover = a / (n * 255);
            data[i] = cover ? Math.round(r / (n * cover)) : 0;
            data[i + 1] = cover ? Math.round(g / (n * cover)) : 0;
            data[i + 2] = cover ? Math.round(b / (n * cover)) : 0;
            data[i + 3] = Math.round(a / n);
        }
    }
    return data;
}

/* ------------------------------------------------------------- PNG writer */

function chunk(type, body) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(body.length);
    const typed = Buffer.concat([Buffer.from(type, 'ascii'), body]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(typed) >>> 0);
    return Buffer.concat([length, typed, crc]);
}

const CRC_TABLE = (() => {
    const table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) { c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); }
        table[n] = c;
    }
    return table;
})();

function crc32(buf) {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) { c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); }
    return c ^ 0xFFFFFFFF;
}

function toPng(rgba, size) {
    const raw = Buffer.alloc((size * 4 + 1) * size);
    for (let y = 0; y < size; y++) {
        raw[y * (size * 4 + 1)] = 0;                                   // filter: none
        rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
    }
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(size, 0);
    ihdr.writeUInt32BE(size, 4);
    ihdr[8] = 8;      // bit depth
    ihdr[9] = 6;      // colour type RGBA
    return Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        chunk('IHDR', ihdr),
        chunk('IDAT', zlib.deflateSync(raw, {level: 9})),
        chunk('IEND', Buffer.alloc(0))
    ]);
}

/* -------------------------------------------------------------------- run */

fs.mkdirSync(OUT_DIR, {recursive: true});
SIZES.forEach((size) => {
    const file = path.join(OUT_DIR, `icon${size}.png`);
    fs.writeFileSync(file, toPng(renderRgba(size), size));
    console.log('wrote', path.relative(process.cwd(), file));
});
