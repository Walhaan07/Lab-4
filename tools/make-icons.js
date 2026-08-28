/*
 * make-icons.js -- generates the extension PNG icons with plain Node.js.
 * Run with:  npm run icons
 *
 * Draws a violet shield disc with a white tick, anti-aliased by 4x
 * supersampling, and writes a valid PNG using only the built-in zlib module.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZES = [16, 48, 128];
const OUT_DIR = path.join(__dirname, '..', 'extension', 'icons');
const SS = 4;                                   // supersampling factor

/* ---------------------------------------------------------------- drawing */

function distanceToSegment(px, py, ax, ay, bx, by) {
    const dx = bx - ax;
    const dy = by - ay;
    const len2 = dx * dx + dy * dy;
    let t = len2 ? ((px - ax) * dx + (py - ay) * dy) / len2 : 0;
    t = Math.max(0, Math.min(1, t));
    const cx = ax + t * dx;
    const cy = ay + t * dy;
    return Math.hypot(px - cx, py - cy);
}

/** Colour of one sample point, in unit coordinates (0..1). */
function sample(u, v) {
    const dx = u - 0.5;
    const dy = v - 0.5;
    const inDisc = Math.hypot(dx, dy) <= 0.47;
    if (!inDisc) { return null; }

    // white tick
    const stroke = 0.055;
    const d = Math.min(
        distanceToSegment(u, v, 0.30, 0.52, 0.44, 0.66),
        distanceToSegment(u, v, 0.44, 0.66, 0.72, 0.34)
    );
    if (d <= stroke) { return [255, 255, 255]; }

    // vertical indigo -> violet gradient
    const t = v;
    return [
        Math.round(79 + (124 - 79) * t),
        Math.round(70 + (58 - 70) * t),
        Math.round(229 + (237 - 229) * t)
    ];
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
