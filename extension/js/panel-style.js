/*
 * panel-style.js  --  design system for the injected button and report panel.
 * ---------------------------------------------------------------------------
 * The CSS lives in a JavaScript string rather than a .css file on purpose.
 *
 *  - The UI is built inside a shadow root, and a stylesheet injected through
 *    the manifest's "css" entry does not cross a shadow boundary.
 *  - Loading it with <link href="chrome-extension://.../panel.css"> works only
 *    where the file is listed in web_accessible_resources, which does not cover
 *    file:/// pages. That is why the button appeared unstyled (and therefore
 *    invisible) on pages opened from disk.
 *
 * Injecting the text directly works on every page the content script reaches,
 * and there is no flash of unstyled content while a stylesheet loads.
 *
 * Everything is driven by the tokens at the top: one neutral ramp, one accent,
 * and five semantic colours shared by the dial, the badges and the findings.
 * Both themes are defined, and the UI follows the reader's system setting
 * rather than the colours of whatever page it is sitting on.
 * ---------------------------------------------------------------------------
 */
window.SSC_PANEL_CSS = `

/* ============================================================ 1. tokens */

:host, :host * { box-sizing: border-box; }

:host {
    /* type */
    --ssc-font: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text",
                "Segoe UI", Roboto, Inter, Helvetica, Arial, sans-serif;
    --ssc-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;

    /* neutrals - light */
    --ssc-surface: #ffffff;
    --ssc-surface-2: #f7f8fb;
    --ssc-surface-3: #eef1f6;
    --ssc-border: rgba(15, 23, 42, .10);
    --ssc-border-2: rgba(15, 23, 42, .16);
    --ssc-text: #0b1020;
    --ssc-text-2: #56607a;
    --ssc-text-3: #667085;              /* 4.8:1 on the panel - AA at 10-12px */
    --ssc-glass: rgba(255, 255, 255, .88);

    /* accent + semantics */
    --ssc-accent: #4f46e5;
    --ssc-accent-2: #7c3aed;
    --ssc-accent-soft: rgba(79, 70, 229, .10);
    --ssc-safe: #12925b;
    --ssc-ok: #4d8c1f;
    --ssc-caution: #c2740a;
    --ssc-risky: #dd5f14;
    --ssc-danger: #d92d20;

    /* Darker pairs for small text sitting on a tinted background: the vivid
       colours above are for graphics (dots, rings) and do not carry enough
       contrast at 10-11px. */
    --ssc-safe-ink: #0b7a4b;
    --ssc-ok-ink: #3f7a17;
    --ssc-caution-ink: #8f5407;
    --ssc-risky-ink: #a94108;
    --ssc-danger-ink: #b42318;

    --ssc-track: rgba(15, 23, 42, .10);
    --ssc-shade: rgba(15, 23, 42, .13);
    --ssc-wash-1: 30%;                  /* verdict wash on the rating block */
    --ssc-wash-2: 16%;

    /* tint backgrounds for findings */
    --ssc-tint-safe: rgba(18, 146, 91, .10);
    --ssc-tint-caution: rgba(194, 116, 10, .10);
    --ssc-tint-danger: rgba(217, 45, 32, .09);

    /* shape + depth */
    --ssc-r-sm: 8px;
    --ssc-r-md: 12px;
    --ssc-r-lg: 16px;
    --ssc-r-pill: 999px;
    --ssc-shadow-1: 0 1px 2px rgba(15, 23, 42, .06), 0 1px 3px rgba(15, 23, 42, .04);
    --ssc-shadow-2: 0 6px 16px -4px rgba(15, 23, 42, .14), 0 2px 6px -2px rgba(15, 23, 42, .07);
    --ssc-shadow-3: 0 28px 64px -16px rgba(15, 23, 42, .30), 0 10px 26px -12px rgba(15, 23, 42, .18);
    --ssc-ring: 0 0 0 3px rgba(79, 70, 229, .35);

    --ssc-ease: cubic-bezier(.22, 1, .36, 1);
}

@media (prefers-color-scheme: dark) {
    :host {
        --ssc-surface: #141a27;
        --ssc-surface-2: #1a2130;
        --ssc-surface-3: #222b3d;
        --ssc-border: rgba(255, 255, 255, .09);
        --ssc-border-2: rgba(255, 255, 255, .16);
        --ssc-text: #eef2f9;
        --ssc-text-2: #a8b3c7;
        --ssc-text-3: #8b96ab;          /* 6:1 on the dark panel */
        --ssc-glass: rgba(20, 26, 39, .88);

        --ssc-accent: #8b83ff;
        --ssc-accent-2: #a78bfa;
        --ssc-accent-soft: rgba(139, 131, 255, .16);
        --ssc-safe: #34d399;
        --ssc-ok: #a3d160;
        --ssc-caution: #fbbf24;
        --ssc-risky: #fb923c;
        --ssc-danger: #fb7185;

        /* on dark, the vivid colours are already the readable ones */
        --ssc-safe-ink: #34d399;
        --ssc-ok-ink: #a3d160;
        --ssc-caution-ink: #fbbf24;
        --ssc-risky-ink: #fb923c;
        --ssc-danger-ink: #fb7185;

        --ssc-track: rgba(255, 255, 255, .10);
        --ssc-shade: rgba(0, 0, 0, .55);
        --ssc-wash-1: 52%;              /* white text, so the wash can be bold */
        --ssc-wash-2: 28%;

        --ssc-tint-safe: rgba(52, 211, 153, .12);
        --ssc-tint-caution: rgba(251, 191, 36, .12);
        --ssc-tint-danger: rgba(251, 113, 133, .12);

        --ssc-shadow-1: 0 1px 2px rgba(0, 0, 0, .4);
        --ssc-shadow-2: 0 6px 18px -4px rgba(0, 0, 0, .5);
        --ssc-shadow-3: 0 28px 64px -16px rgba(0, 0, 0, .66), 0 10px 26px -12px rgba(0, 0, 0, .5);
        --ssc-ring: 0 0 0 3px rgba(139, 131, 255, .45);
    }
}

/* one place to map a verdict onto its colour */
/*
 * Each verdict carries a gradient as well as a flat colour. The gradients are
 * chosen so that the text sitting on them keeps its contrast: the cyan, amber
 * and orange ramps are bright and take dark ink, while the red ramp is deep
 * enough to take white. A light gradient with white text would look striking
 * and be unreadable.
 */
.ssc-level--safe    { --ssc-level: var(--ssc-safe);    --ssc-level-ink: var(--ssc-safe-ink);
                      --ssc-level-tint: var(--ssc-tint-safe); }
.ssc-level--ok      { --ssc-level: var(--ssc-ok);      --ssc-level-ink: var(--ssc-ok-ink);
                      --ssc-level-tint: var(--ssc-tint-safe); }
.ssc-level--caution { --ssc-level: var(--ssc-caution); --ssc-level-ink: var(--ssc-caution-ink);
                      --ssc-level-tint: var(--ssc-tint-caution); }
.ssc-level--risky   { --ssc-level: var(--ssc-risky);   --ssc-level-ink: var(--ssc-risky-ink);
                      --ssc-level-tint: var(--ssc-tint-caution); }
.ssc-level--danger  { --ssc-level: var(--ssc-danger);  --ssc-level-ink: var(--ssc-danger-ink);
                      --ssc-level-tint: var(--ssc-tint-danger); }

/*
 * The ramps run deep enough that white text clears AA on every stop, and each
 * one carries a bright glow of its own hue. That keeps the cyan reading as
 * cyan while the label stays legible - a pale gradient with white text looks
 * striking in a mockup and is unreadable in use.
 */
.ssc-level--safe, .ssc-level--ok {
    --ssc-grad-1: #075985;              /* white: 7.6:1 */
    --ssc-grad-2: #0e7490;              /* white: 5.4:1 */
    --ssc-grad-3: #0f766e;              /* white: 5.6:1 */
    --ssc-glow: rgba(34, 211, 238, .8);
    --ssc-arc-1: #0ea5e9;               /* the ring and the card wash stay bright */
    --ssc-arc-2: #22d3ee;
    --ssc-arc-3: #5eead4;
    --ssc-pill-ink: #ffffff;
    --ssc-pill-ink-2: rgba(236, 254, 255, .82);
    --ssc-pill-token: #0b4f5e;
}
.ssc-level--caution {
    --ssc-grad-1: #92400e;
    --ssc-grad-2: #b45309;
    --ssc-grad-3: #c2740a;              /* white: 4.6:1 */
    --ssc-glow: rgba(251, 191, 36, .7);
    --ssc-arc-1: #f59e0b;
    --ssc-arc-2: #fbbf24;
    --ssc-arc-3: #fcd34d;
    --ssc-pill-ink: #ffffff;
    --ssc-pill-ink-2: rgba(255, 251, 235, .84);
    --ssc-pill-token: #7c3d06;
}
.ssc-level--risky {
    --ssc-grad-1: #9a3412;
    --ssc-grad-2: #c2410c;
    --ssc-grad-3: #dd5f14;              /* white: 4.5:1 */
    --ssc-glow: rgba(251, 146, 60, .7);
    --ssc-arc-1: #ea580c;
    --ssc-arc-2: #f97316;
    --ssc-arc-3: #fb923c;
    --ssc-pill-ink: #ffffff;
    --ssc-pill-ink-2: rgba(255, 247, 237, .84);
    --ssc-pill-token: #7c2d12;
}
.ssc-level--danger {
    /* The brightest red that still carries white text: #ef4444 would look
       hotter but drops to 3.8:1, so the ramp tops out at a crimson-rose and
       the heat comes from the glow instead. */
    --ssc-grad-1: #c81111;              /* white: 5.4:1 */
    --ssc-grad-2: #dc2626;              /* white: 4.5:1 */
    --ssc-grad-3: #e11d48;              /* white: 4.7:1 */
    --ssc-glow: rgba(255, 70, 70, .95);
    --ssc-arc-1: #ef4444;
    --ssc-arc-2: #f43f5e;
    --ssc-arc-3: #fb7185;
    --ssc-pill-ink: #ffffff;
    --ssc-pill-ink-2: rgba(255, 241, 242, .88);
    --ssc-pill-token: #be123c;
}

/* ============================================================ 2. button */

/* the pill and its collapse toggle, anchored together at the corner */
.ssc-dock {
    position: absolute;
    right: 0;
    bottom: 0;
    display: flex;
    align-items: center;
    gap: 7px;
}

.ssc-dock__toggle {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    flex: 0 0 auto;
    padding: 0;
    border: 1px solid var(--ssc-border-2);
    border-radius: 50%;
    background: var(--ssc-glass);
    -webkit-backdrop-filter: blur(16px) saturate(1.6);
    backdrop-filter: blur(16px) saturate(1.6);
    color: var(--ssc-text-3);
    cursor: pointer;
    opacity: .55;
    box-shadow: var(--ssc-shadow-1);
    transition: opacity .15s var(--ssc-ease), color .15s var(--ssc-ease),
                border-color .15s var(--ssc-ease);
}
.ssc-dock:hover .ssc-dock__toggle { opacity: 1; }
.ssc-dock__toggle:hover { color: var(--ssc-text); border-color: var(--ssc-accent); }
.ssc-dock__toggle:focus-visible { opacity: 1; outline: none; box-shadow: var(--ssc-ring); }
.ssc-dock__toggle svg { width: 12px; height: 12px; display: block; }

.ssc-button {
    display: inline-flex;
    align-items: center;
    gap: 9px;
    max-width: 460px;
    margin: 0;
    padding: 10px 11px 10px 14px;
    border: 1px solid var(--ssc-border-2);
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-glass);
    -webkit-backdrop-filter: blur(16px) saturate(1.6);
    backdrop-filter: blur(16px) saturate(1.6);
    color: var(--ssc-text);
    /* line-height 1 clipped the descenders of letters such as g and p in the
       URL, so the text is given room to sit in. */
    font: 500 13px/1.45 var(--ssc-font);
    letter-spacing: -.005em;
    cursor: grab;
    touch-action: none;
    user-select: none;
    white-space: nowrap;
    box-shadow: var(--ssc-shadow-2);
    transition: transform .18s var(--ssc-ease), box-shadow .18s var(--ssc-ease),
                border-color .18s var(--ssc-ease);
}

.ssc-button:hover {
    transform: translateY(-1px);
    border-color: var(--ssc-accent);
    box-shadow: var(--ssc-shadow-3);
}

.ssc-button:active { transform: translateY(0); }
.ssc-button:focus-visible { outline: none; box-shadow: var(--ssc-shadow-2), var(--ssc-ring); }

/* Once a page has been rated the pill carries the verdict's colour, so the
   result is readable without opening the report. */
.ssc-button--rated {
    background:
        /* a bright rim along the top edge keeps the deep ramp from looking flat */
        linear-gradient(180deg, rgba(255, 255, 255, .22), rgba(255, 255, 255, 0) 46%),
        linear-gradient(120deg, var(--ssc-grad-1), var(--ssc-grad-2) 52%, var(--ssc-grad-3));
    border-color: rgba(255, 255, 255, .22);
    color: var(--ssc-pill-ink);
    -webkit-backdrop-filter: none;
    backdrop-filter: none;
    box-shadow: var(--ssc-shadow-2), 0 10px 30px -10px var(--ssc-glow),
                inset 0 1px 0 rgba(255, 255, 255, .3);
}

.ssc-button--rated .ssc-button__lead { color: var(--ssc-pill-ink-2); }
.ssc-button--rated .ssc-button__mark { color: #fff; }
.ssc-button--rated:hover {
    border-color: rgba(255, 255, 255, .5);
    box-shadow: var(--ssc-shadow-3), 0 12px 32px -8px var(--ssc-glow),
                inset 0 1px 0 rgba(255, 255, 255, .3);
}

/* the rating token: a bright disc with the letter cut into the verdict colour */
.ssc-button--rated .ssc-button__badge {
    background: linear-gradient(180deg, #ffffff, #eef2f7);
    color: var(--ssc-pill-token);
    box-shadow: 0 1px 2px rgba(0, 0, 0, .28), inset 0 0 0 1px rgba(255, 255, 255, .9);
    letter-spacing: -.02em;
}

.ssc-button--dragging {
    cursor: grabbing;
    transition: none;
    transform: scale(1.02);
    box-shadow: var(--ssc-shadow-3);
}

.ssc-button__mark {
    display: inline-flex;
    flex: 0 0 auto;
    width: 19px;
    height: 19px;
    color: var(--ssc-accent);
}
.ssc-button__mark svg { width: 100%; height: 100%; display: block; }

.ssc-button__label {
    display: inline-flex;
    align-items: baseline;
    gap: 6px;
    min-width: 0;
    line-height: 1.45;      /* keeps descenders inside the clipping box */
}

.ssc-button__lead { color: var(--ssc-text-3); font-weight: 500; }

.ssc-button__url {
    font-weight: 650;
    letter-spacing: -.01em;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.ssc-button__badge[hidden] { display: none; }

/* collapsed: a circle carrying just the rating */
.ssc-button--mini {
    width: 46px;
    height: 46px;
    max-width: none;
    padding: 0;
    gap: 0;
    justify-content: center;
    border-radius: 50%;
}
.ssc-button--mini .ssc-button__label { display: none; }
.ssc-button--mini.ssc-button--has-rating .ssc-button__mark { display: none; }
.ssc-button--mini .ssc-button__mark { width: 21px; height: 21px; }

/* inside the circle the letter stands alone, without a second disc */
.ssc-button--mini .ssc-button__badge {
    width: auto;
    height: auto;
    background: none;
    box-shadow: none;
    color: var(--ssc-pill-ink, var(--ssc-text));
    font-size: 17px;
    font-weight: 700;
    letter-spacing: -.02em;
}

.ssc-button__badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
    width: 23px;
    height: 23px;
    border-radius: 50%;
    background: var(--ssc-level, var(--ssc-text-3));
    color: #fff;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0;
    box-shadow: inset 0 0 0 1px rgba(255, 255, 255, .18), 0 1px 2px rgba(0, 0, 0, .2);
}

/* ============================================================= 3. panel */

.ssc-panel {
    position: absolute;
    right: 0;
    bottom: 46px;
    display: flex;
    flex-direction: column;
    width: 384px;
    max-width: calc(100vw - 36px);
    max-height: min(72vh, 640px);
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-lg);
    background: var(--ssc-surface);
    color: var(--ssc-text);
    font: 400 13px/1.55 var(--ssc-font);
    box-shadow: var(--ssc-shadow-3);
    overflow: hidden;
    transform-origin: bottom right;
    animation: ssc-in .24s var(--ssc-ease) both;
}

.ssc-panel[hidden] { display: none; }
.ssc-panel--below { top: 46px; bottom: auto; transform-origin: top right; }

.ssc-panel--left  { right: auto; left: 0; transform-origin: bottom left; }
.ssc-panel--below.ssc-panel--left { transform-origin: top left; }

@keyframes ssc-in {
    from { opacity: 0; transform: translateY(6px) scale(.98); }
    to   { opacity: 1; transform: none; }
}

.ssc-panel__head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 13px 14px;
    border-bottom: 1px solid var(--ssc-border);
    background: var(--ssc-surface-2);
}

.ssc-panel__mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    flex: 0 0 auto;
    border-radius: 9px;
    background: var(--ssc-accent-soft);
    color: var(--ssc-accent);
}
.ssc-panel__mark svg { width: 17px; height: 17px; display: block; }

.ssc-panel__heading { display: flex; flex-direction: column; gap: 1px; min-width: 0; flex: 1 1 auto; }

.ssc-panel__title {
    margin: 0;
    font-size: 13.5px;
    font-weight: 650;
    letter-spacing: -.012em;
}

.ssc-panel__subtitle {
    margin: 0;
    color: var(--ssc-text-3);
    font-size: 11px;
    letter-spacing: .002em;
}

.ssc-icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    flex: 0 0 auto;
    padding: 0;
    border: 0;
    border-radius: var(--ssc-r-sm);
    background: transparent;
    color: var(--ssc-text-3);
    cursor: pointer;
    transition: background .15s var(--ssc-ease), color .15s var(--ssc-ease);
}
.ssc-icon-btn:hover { background: var(--ssc-surface-3); color: var(--ssc-text); }
.ssc-icon-btn:focus-visible { outline: none; box-shadow: var(--ssc-ring); }
.ssc-icon-btn svg { width: 15px; height: 15px; display: block; }

/*
 * The two radial gradients are pinned to the scroll container and the two
 * linear ones scroll with the content, so a soft shadow appears at an edge
 * only while there is more to scroll in that direction.
 */
.ssc-panel__body {
    padding: 14px;
    overflow-y: auto;
    overscroll-behavior: contain;
    background:
        linear-gradient(var(--ssc-surface) 40%, transparent) top / 100% 22px no-repeat local,
        linear-gradient(transparent, var(--ssc-surface) 60%) bottom / 100% 22px no-repeat local,
        radial-gradient(farthest-side at 50% 0, var(--ssc-shade), transparent) top / 100% 10px no-repeat scroll,
        radial-gradient(farthest-side at 50% 100%, var(--ssc-shade), transparent) bottom / 100% 10px no-repeat scroll,
        var(--ssc-surface);
    scrollbar-width: thin;
    scrollbar-color: var(--ssc-border-2) transparent;
}
.ssc-panel__body::-webkit-scrollbar { width: 10px; }
.ssc-panel__body::-webkit-scrollbar-thumb {
    border: 3px solid transparent;
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-border-2);
    background-clip: content-box;
}

.ssc-panel__foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 14px;
    border-top: 1px solid var(--ssc-border);
    background: var(--ssc-surface-2);
}

.ssc-foot__note { color: var(--ssc-text-3); font-size: 10.5px; letter-spacing: .002em; }

.ssc-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 11px;
    border: 1px solid var(--ssc-border-2);
    border-radius: var(--ssc-r-sm);
    background: var(--ssc-surface);
    color: var(--ssc-text);
    font: 550 11.5px/1 var(--ssc-font);
    cursor: pointer;
    transition: background .15s var(--ssc-ease), border-color .15s var(--ssc-ease);
}
.ssc-btn:hover { background: var(--ssc-surface-3); border-color: var(--ssc-accent); }
.ssc-btn:focus-visible { outline: none; box-shadow: var(--ssc-ring); }
.ssc-btn svg { width: 13px; height: 13px; }

/* ========================================================== 4. verdict */

/*
 * The verdict block is painted with the same gradient as the button, not a
 * wash of it: a translucent tint over a dark panel turns any bright colour to
 * mud, which is why the alarm red read as plum here while the pill was vivid.
 * Carrying the real ramp means the text on it switches to the pill's ink, and
 * the ring inside it goes white so the score still stands out.
 */
.ssc-summary {
    position: relative;
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 16px 15px;
    border: 1px solid rgba(255, 255, 255, .18);
    border-radius: var(--ssc-r-md);
    background:
        linear-gradient(180deg, rgba(255, 255, 255, .18), rgba(255, 255, 255, 0) 46%),
        linear-gradient(120deg, var(--ssc-grad-1), var(--ssc-grad-2) 52%, var(--ssc-grad-3));
    color: var(--ssc-pill-ink, var(--ssc-text));
    box-shadow: 0 14px 32px -16px var(--ssc-glow, transparent),
                inset 0 1px 0 rgba(255, 255, 255, .22);

    /* Secondary text on a saturated fill needs to stay close to white: the
       pill's translucent ink measures 3.65:1 at this size. */
    --ssc-card-ink-2: rgba(255, 255, 255, .98);

    /* the ring reads as white on the coloured card */
    --ssc-ring-1: #ffffff;
    --ssc-ring-2: rgba(255, 255, 255, .94);
    --ssc-ring-3: rgba(255, 255, 255, .84);
}

/* Nothing has been scanned yet: keep the neutral card. */
.ssc-summary:not([class*="ssc-level--"]) {
    border-color: var(--ssc-border);
    background: var(--ssc-surface-2);
    color: var(--ssc-text);
    --ssc-card-ink-2: var(--ssc-text-2);
    --ssc-ring-1: var(--ssc-accent);
    --ssc-ring-2: var(--ssc-accent);
    --ssc-ring-3: var(--ssc-accent);
}

.ssc-ring { position: relative; flex: 0 0 auto; width: 84px; height: 84px; }
.ssc-ring__svg { width: 100%; height: 100%; display: block; transform: rotate(-90deg); }
.ssc-ring__track { fill: none; stroke: rgba(255, 255, 255, .24); stroke-width: 7.5; }

.ssc-ring__arc {
    fill: none;
    stroke: var(--ssc-level, var(--ssc-accent));   /* replaced by the gradient below */
    stroke-width: 7.5;
    stroke-linecap: round;
    transition: stroke-dashoffset .85s var(--ssc-ease);
}

.ssc-ring__value {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1;
}

.ssc-ring__score {
    font-size: 23px;
    font-weight: 700;
    letter-spacing: -.03em;
    font-variant-numeric: tabular-nums;
    font-feature-settings: "tnum" 1;
}

.ssc-ring__max {
    margin-top: 3px;
    color: var(--ssc-card-ink-2, var(--ssc-text-3));
    font-size: 9.5px;
    font-weight: 600;
    letter-spacing: .04em;
}

.ssc-summary__text { display: flex; flex-direction: column; gap: 5px; min-width: 0; }

.ssc-chip {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 9px;
    border-radius: var(--ssc-r-pill);
    /* its own ground, so it stays legible on top of the verdict wash */
    background: var(--ssc-surface);
    border: 1px solid rgba(255, 255, 255, .3);
    box-shadow: 0 1px 3px rgba(0, 0, 0, .18);
    color: var(--ssc-level-ink, var(--ssc-text-2));
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: .05em;
    text-transform: uppercase;
}

.ssc-summary__verdict {
    font-size: 17px;
    font-weight: 650;
    letter-spacing: -.02em;
    line-height: 1.2;
}

.ssc-summary__host {
    color: var(--ssc-card-ink-2, var(--ssc-text-2));
    font-size: 12px;
    font-family: var(--ssc-mono);
    overflow-wrap: anywhere;
}

/* severity tally */
.ssc-tally {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 10px;
}

.ssc-tally__item {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-surface-2);
    color: var(--ssc-text-2);
    font: 500 11px/1.4 var(--ssc-font);
    cursor: pointer;
    transition: border-color .15s var(--ssc-ease), background .15s var(--ssc-ease),
                transform .15s var(--ssc-ease);
}
.ssc-tally__item:hover {
    background: var(--ssc-surface-3);
    border-color: color-mix(in srgb, var(--ssc-dot, var(--ssc-accent)) 55%, transparent);
    transform: translateY(-1px);
}
.ssc-tally__item:active { transform: none; }
.ssc-tally__item:focus-visible { outline: none; box-shadow: var(--ssc-ring); }
.ssc-tally__dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ssc-dot, var(--ssc-text-3)); }
.ssc-tally__item b { color: var(--ssc-text); font-weight: 650; font-variant-numeric: tabular-nums; }

.ssc-url {
    margin: 10px 0 0;
    padding: 9px 11px;
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-sm);
    background: var(--ssc-surface-2);
    color: var(--ssc-text-2);
    font-family: var(--ssc-mono);
    font-size: 11px;
    line-height: 1.5;
    overflow-wrap: anywhere;
}

.ssc-cap {
    display: flex;
    gap: 8px;
    margin: 10px 0 0;
    padding: 10px 11px;
    border: 1px solid color-mix(in srgb, var(--ssc-danger) 32%, transparent);
    border-radius: var(--ssc-r-sm);
    background: var(--ssc-tint-danger);
    color: var(--ssc-text);
    font-size: 11.5px;
    line-height: 1.5;
}
.ssc-cap svg { flex: 0 0 auto; width: 14px; height: 14px; margin-top: 1px; color: var(--ssc-danger); }

/* ========================================================= 5. findings */

.ssc-section { margin-top: 18px; }

.ssc-section__title {
    display: flex;
    align-items: center;
    gap: 7px;
    margin: 0 0 8px;
    color: var(--ssc-text-3);
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: .09em;
    text-transform: uppercase;
}

.ssc-count {
    padding: 1px 6px;
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-surface-3);
    color: var(--ssc-text-2);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0;
    font-variant-numeric: tabular-nums;
}

.ssc-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }

.ssc-item {
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-md);
    background: var(--ssc-surface);
    transition: border-color .15s var(--ssc-ease), background .15s var(--ssc-ease);
}
.ssc-item:hover { border-color: var(--ssc-border-2); }

/* the whole row is the control that opens the explanation */
.ssc-item__summary {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 10px 11px;
    border-radius: var(--ssc-r-md);
    cursor: pointer;
    list-style: none;
    user-select: none;
}
.ssc-item__summary::-webkit-details-marker { display: none; }
.ssc-item__summary:focus-visible { outline: none; box-shadow: var(--ssc-ring); }

.ssc-item__chevron {
    flex: 0 0 auto;
    width: 13px;
    height: 13px;
    margin-top: 3px;
    color: var(--ssc-text-3);
    transition: transform .2s var(--ssc-ease);
}
.ssc-item__box[open] > .ssc-item__summary > .ssc-item__chevron { transform: rotate(90deg); }

.ssc-item__about {
    padding: 0 12px 11px 29px;
    color: var(--ssc-text-2);
    font-size: 11.5px;
    line-height: 1.6;
}
.ssc-item__about p { margin: 0; padding-top: 9px; border-top: 1px solid var(--ssc-border); }

.ssc-item--high   { --ssc-dot: var(--ssc-danger); --ssc-ink: var(--ssc-danger-ink);
                    background: var(--ssc-tint-danger);
                    border-color: color-mix(in srgb, var(--ssc-danger) 22%, transparent); }
.ssc-item--medium { --ssc-dot: var(--ssc-caution); --ssc-ink: var(--ssc-caution-ink);
                    background: var(--ssc-tint-caution);
                    border-color: color-mix(in srgb, var(--ssc-caution) 22%, transparent); }
.ssc-item--low    { --ssc-dot: var(--ssc-text-3); --ssc-ink: var(--ssc-text-2); }
.ssc-item--pass   { --ssc-dot: var(--ssc-safe); --ssc-ink: var(--ssc-safe-ink); }
.ssc-item--pass .ssc-item__summary { padding: 8px 11px; }

/* a brief ring on whichever check the tally jumped to */
.ssc-item--flash {
    animation: ssc-flash 1.3s var(--ssc-ease);
}
@keyframes ssc-flash {
    0%, 100% { box-shadow: 0 0 0 0 transparent; }
    12%, 55% { box-shadow: 0 0 0 3px color-mix(in srgb, var(--ssc-dot) 40%, transparent); }
}

.ssc-item__dot {
    flex: 0 0 auto;
    width: 8px;
    height: 8px;
    margin-top: 6px;
    border-radius: 50%;
    background: var(--ssc-dot);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--ssc-dot) 18%, transparent);
}

.ssc-item__text { display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1 1 auto; }

.ssc-item__row { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }

.ssc-item__title {
    font-size: 12.5px;
    font-weight: 600;
    letter-spacing: -.008em;
    line-height: 1.35;
}

.ssc-item__points {
    flex: 0 0 auto;
    color: var(--ssc-ink, var(--ssc-text-2));
    font-family: var(--ssc-mono);
    font-size: 11px;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
}

.ssc-item__detail { margin: 0; color: var(--ssc-text-2); font-size: 11.5px; line-height: 1.5; word-break: break-word; }

.ssc-clean {
    display: flex;
    align-items: center;
    gap: 11px;
    margin-top: 14px;
    padding: 14px;
    border: 1px solid color-mix(in srgb, var(--ssc-safe) 26%, transparent);
    border-radius: var(--ssc-r-md);
    background: var(--ssc-tint-safe);
}
.ssc-clean__icon {
    display: inline-flex; align-items: center; justify-content: center;
    width: 30px; height: 30px; flex: 0 0 auto;
    border-radius: 50%;
    background: var(--ssc-safe);
    color: var(--ssc-surface);
}
.ssc-clean__icon svg { width: 17px; height: 17px; }
.ssc-clean__text { display: flex; flex-direction: column; gap: 1px; }
.ssc-clean__title { font-size: 12.5px; font-weight: 650; }
.ssc-clean__note { color: var(--ssc-text-2); font-size: 11.5px; }

/* passed tests, folded away */
.ssc-disclosure { margin-top: 14px; border-top: 1px solid var(--ssc-border); padding-top: 12px; }

.ssc-disclosure__summary {
    display: flex;
    align-items: center;
    gap: 7px;
    color: var(--ssc-text-2);
    font-size: 11.5px;
    font-weight: 600;
    cursor: pointer;
    list-style: none;
    user-select: none;
}
.ssc-disclosure__summary::-webkit-details-marker { display: none; }
.ssc-disclosure__summary:hover { color: var(--ssc-text); }
.ssc-disclosure__summary:focus-visible { outline: none; box-shadow: var(--ssc-ring); border-radius: var(--ssc-r-sm); }

.ssc-disclosure__chevron { width: 13px; height: 13px; transition: transform .2s var(--ssc-ease); }
.ssc-disclosure[open] .ssc-disclosure__chevron { transform: rotate(90deg); }
.ssc-disclosure .ssc-list { margin-top: 9px; }

.ssc-loading {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 0;
    padding: 26px 4px;
    justify-content: center;
    color: var(--ssc-text-2);
    font-size: 12.5px;
}
.ssc-spinner {
    width: 15px; height: 15px;
    border: 2px solid var(--ssc-surface-3);
    border-top-color: var(--ssc-accent);
    border-radius: 50%;
    animation: ssc-spin .7s linear infinite;
}
@keyframes ssc-spin { to { transform: rotate(360deg); } }

.ssc-skipped { margin: 12px 0 0; color: var(--ssc-text-3); font-size: 10.5px; }

@media (prefers-reduced-motion: reduce) {
    .ssc-panel { animation: none; }
    .ssc-ring__arc { transition: none; }
    .ssc-spinner { animation-duration: 2s; }
    .ssc-button, .ssc-item, .ssc-btn, .ssc-icon-btn, .ssc-tally__item,
    .ssc-item__chevron, .ssc-disclosure__chevron { transition: none; }
    .ssc-item--flash { animation: none; outline: 2px solid var(--ssc-dot); }
}

`;
