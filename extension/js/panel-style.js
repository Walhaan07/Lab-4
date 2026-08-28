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

/* ============================================================ 2. button */

.ssc-button {
    position: absolute;
    right: 0;
    bottom: 0;
    display: inline-flex;
    align-items: center;
    gap: 9px;
    max-width: 420px;
    margin: 0;
    padding: 8px 10px 8px 12px;
    border: 1px solid var(--ssc-border-2);
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-glass);
    -webkit-backdrop-filter: blur(16px) saturate(1.6);
    backdrop-filter: blur(16px) saturate(1.6);
    color: var(--ssc-text);
    font: 500 12.5px/1 var(--ssc-font);
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

.ssc-button--dragging {
    cursor: grabbing;
    transition: none;
    transform: scale(1.02);
    box-shadow: var(--ssc-shadow-3);
}

.ssc-button__mark {
    display: inline-flex;
    flex: 0 0 auto;
    width: 18px;
    height: 18px;
    color: var(--ssc-accent);
}
.ssc-button__mark svg { width: 100%; height: 100%; display: block; }

.ssc-button__label {
    display: inline-flex;
    align-items: baseline;
    gap: 5px;
    min-width: 0;
    overflow: hidden;
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

.ssc-button__badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
    width: 21px;
    height: 21px;
    border-radius: 50%;
    background: var(--ssc-level, var(--ssc-text-3));
    color: #fff;
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0;
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--ssc-level, #888) 18%, transparent);
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

.ssc-summary {
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 15px;
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-md);
    background:
        radial-gradient(120% 140% at 100% 0%, var(--ssc-level-tint, transparent) 0%, transparent 62%),
        var(--ssc-surface-2);
}

.ssc-ring { position: relative; flex: 0 0 auto; width: 84px; height: 84px; }
.ssc-ring__svg { width: 100%; height: 100%; display: block; transform: rotate(-90deg); }
.ssc-ring__track { fill: none; stroke: var(--ssc-track); stroke-width: 7.5; }

.ssc-ring__arc {
    fill: none;
    stroke: var(--ssc-level, var(--ssc-accent));
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

.ssc-ring__max { margin-top: 3px; color: var(--ssc-text-3); font-size: 9.5px; font-weight: 600; letter-spacing: .04em; }

.ssc-summary__text { display: flex; flex-direction: column; gap: 5px; min-width: 0; }

.ssc-chip {
    align-self: flex-start;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-level-tint, var(--ssc-surface-3));
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
    color: var(--ssc-text-2);
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
    padding: 3px 9px;
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-pill);
    background: var(--ssc-surface-2);
    color: var(--ssc-text-2);
    font-size: 11px;
    font-weight: 500;
}
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
    display: flex;
    gap: 10px;
    padding: 10px 11px;
    border: 1px solid var(--ssc-border);
    border-radius: var(--ssc-r-md);
    background: var(--ssc-surface);
    transition: border-color .15s var(--ssc-ease), background .15s var(--ssc-ease);
}
.ssc-item:hover { border-color: var(--ssc-border-2); background: var(--ssc-surface-2); }

.ssc-item--high   { --ssc-dot: var(--ssc-danger); --ssc-ink: var(--ssc-danger-ink);
                    background: var(--ssc-tint-danger);
                    border-color: color-mix(in srgb, var(--ssc-danger) 22%, transparent); }
.ssc-item--medium { --ssc-dot: var(--ssc-caution); --ssc-ink: var(--ssc-caution-ink);
                    background: var(--ssc-tint-caution);
                    border-color: color-mix(in srgb, var(--ssc-caution) 22%, transparent); }
.ssc-item--low    { --ssc-dot: var(--ssc-text-3); --ssc-ink: var(--ssc-text-2); }
.ssc-item--pass   { --ssc-dot: var(--ssc-safe); --ssc-ink: var(--ssc-safe-ink); padding: 7px 11px; }

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
    .ssc-button, .ssc-item, .ssc-btn, .ssc-icon-btn { transition: none; }
}

`;
