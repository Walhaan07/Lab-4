/*
 * panel-style.js  --  styles for the injected button and report panel.
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
 * ---------------------------------------------------------------------------
 */
window.SSC_PANEL_CSS = `
/*
 * These rules are injected into the shadow root, so they cannot affect the
 * host page and the host page cannot affect them.
 */

:host, * { box-sizing: border-box; }

:root, :host {
    --ssc-font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    --ssc-safe: #16a34a;
    --ssc-ok: #65a30d;
    --ssc-caution: #d97706;
    --ssc-risky: #ea580c;
    --ssc-danger: #dc2626;
}

/* ------------------------------------------------------------- the button */

.ssc-button {
    position: fixed;
    right: 18px;
    bottom: 18px;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 420px;
    margin: 0;
    padding: 10px 14px;
    border: 0;
    border-radius: 999px;
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    color: #fff;
    font: 500 13px/1.3 var(--ssc-font);
    letter-spacing: .1px;
    cursor: pointer;
    box-shadow: 0 6px 20px rgba(15, 23, 42, .28);
    transition: transform .15s ease, box-shadow .15s ease;
}

.ssc-button:hover { transform: translateY(-1px); box-shadow: 0 10px 26px rgba(15, 23, 42, .34); }
.ssc-button:active { transform: translateY(0); }
.ssc-button:focus-visible { outline: 3px solid #fbbf24; outline-offset: 2px; }

.ssc-button__icon { font-size: 15px; line-height: 1; }

.ssc-button__label {
    display: inline-block;
    max-width: 330px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.ssc-button__lead { opacity: .85; }
.ssc-button__url { font-weight: 700; }

/* [hidden] must beat the class rule below, or an empty badge circle is shown
   on the button before the first scan. */
.ssc-button__badge[hidden] { display: none; }

.ssc-button__badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: #fff;
    color: #111827;
    font-weight: 800;
    font-size: 12px;
}

.ssc-button__badge.ssc-level--safe   { background: var(--ssc-safe);    color: #fff; }
.ssc-button__badge.ssc-level--ok     { background: var(--ssc-ok);      color: #fff; }
.ssc-button__badge.ssc-level--caution{ background: var(--ssc-caution); color: #fff; }
.ssc-button__badge.ssc-level--risky  { background: var(--ssc-risky);   color: #fff; }
.ssc-button__badge.ssc-level--danger { background: var(--ssc-danger);  color: #fff; }

/* -------------------------------------------------------------- the panel */

.ssc-panel {
    position: fixed;
    right: 18px;
    bottom: 74px;
    display: flex;
    flex-direction: column;
    width: 380px;
    max-width: calc(100vw - 36px);
    max-height: min(70vh, 620px);
    border-radius: 14px;
    background: #ffffff;
    color: #0f172a;
    font: 400 13px/1.5 var(--ssc-font);
    box-shadow: 0 18px 48px rgba(15, 23, 42, .3);
    overflow: hidden;
}

.ssc-panel[hidden] { display: none; }

.ssc-panel__head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: #0f172a;
    color: #fff;
}

.ssc-panel__title { margin: 0; font-size: 13px; font-weight: 600; letter-spacing: .2px; }

.ssc-panel__close {
    border: 0;
    background: transparent;
    color: #cbd5f5;
    font-size: 20px;
    line-height: 1;
    cursor: pointer;
    padding: 0 4px;
}
.ssc-panel__close:hover { color: #fff; }

.ssc-panel__body { padding: 14px; overflow-y: auto; }

.ssc-panel__foot {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 14px;
    border-top: 1px solid #e2e8f0;
    background: #f8fafc;
}

.ssc-foot__note { color: #64748b; font-size: 11px; }

.ssc-btn {
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    background: #fff;
    color: #0f172a;
    padding: 6px 10px;
    font: 500 12px var(--ssc-font);
    cursor: pointer;
}
.ssc-btn:hover { background: #eef2ff; border-color: #a5b4fc; }

/* ------------------------------------------------------------ the verdict */

.ssc-verdict {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 12px;
    border-radius: 12px;
    border: 1px solid #e2e8f0;
    background: #f8fafc;
}

.ssc-dial {
    --ssc-score: 0;
    --ssc-colour: #64748b;
    position: relative;
    flex: 0 0 auto;
    width: 76px;
    height: 76px;
    border-radius: 50%;
    background: conic-gradient(var(--ssc-colour) calc(var(--ssc-score) * 1%), #e2e8f0 0);
    color: #0f172a;
}

/* The number is centred inside its own disc rather than laid out as a row in
   the ring: that keeps 0, 87 and 100 all optically centred. */
.ssc-dial__inner {
    position: absolute;
    inset: 7px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: #fff;
    line-height: 1;
}

.ssc-dial__score { font-size: 21px; font-weight: 800; letter-spacing: -.5px; }
.ssc-dial__max   { margin-top: 3px; font-size: 9px; font-weight: 600; color: #64748b; letter-spacing: .2px; }

.ssc-level--safe    .ssc-dial { --ssc-colour: var(--ssc-safe); }
.ssc-level--ok      .ssc-dial { --ssc-colour: var(--ssc-ok); }
.ssc-level--caution .ssc-dial { --ssc-colour: var(--ssc-caution); }
.ssc-level--risky   .ssc-dial { --ssc-colour: var(--ssc-risky); }
.ssc-level--danger  .ssc-dial { --ssc-colour: var(--ssc-danger); }

.ssc-verdict__text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }

.ssc-verdict__grade {
    align-self: flex-start;
    padding: 1px 8px;
    border-radius: 999px;
    background: #e2e8f0;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .4px;
}

.ssc-level--safe    .ssc-verdict__grade { background: #dcfce7; color: #14532d; }
.ssc-level--ok      .ssc-verdict__grade { background: #ecfccb; color: #365314; }
.ssc-level--caution .ssc-verdict__grade { background: #fef3c7; color: #78350f; }
.ssc-level--risky   .ssc-verdict__grade { background: #ffedd5; color: #7c2d12; }
.ssc-level--danger  .ssc-verdict__grade { background: #fee2e2; color: #7f1d1d; }

.ssc-verdict__word { font-size: 16px; font-weight: 700; }
.ssc-verdict__host { color: #334155; word-break: break-all; font-size: 12px; }
.ssc-verdict__count { color: #64748b; font-size: 11px; }

.ssc-url {
    margin: 12px 0 4px;
    padding: 8px 10px;
    border-radius: 8px;
    background: #eef2ff;
    color: #312e81;
    font-size: 11.5px;
    word-break: break-all;
}

/* -------------------------------------------------------------- test list */

.ssc-section { margin: 14px 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .6px; color: #64748b; }

.ssc-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }

.ssc-item {
    display: flex;
    gap: 9px;
    padding: 8px 10px;
    border-radius: 9px;
    border-left: 3px solid #cbd5e1;
    background: #f8fafc;
}

.ssc-item--high   { border-left-color: var(--ssc-danger);  background: #fef2f2; }
.ssc-item--medium { border-left-color: var(--ssc-caution); background: #fffbeb; }
.ssc-item--low    { border-left-color: #94a3b8; }
.ssc-item--pass   { border-left-color: var(--ssc-safe); background: #f6fdf8; }

.ssc-item__points {
    flex: 0 0 auto;
    min-width: 24px;
    text-align: center;
    font-weight: 700;
    font-size: 11px;
    color: #b91c1c;
}
.ssc-item--pass .ssc-item__points { color: var(--ssc-safe); }

.ssc-item__text { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ssc-item__title { font-weight: 600; font-size: 12px; }
.ssc-item__detail { color: #475569; font-size: 11.5px; word-break: break-word; }

.ssc-cap {
    margin: 8px 0 0;
    padding: 8px 10px;
    border-radius: 8px;
    border-left: 3px solid var(--ssc-danger);
    background: #fef2f2;
    color: #7f1d1d;
    font-size: 11.5px;
}

.ssc-clean { margin: 12px 0 0; padding: 10px; border-radius: 9px; background: #f0fdf4; color: #14532d; }
.ssc-loading { margin: 0; padding: 22px 6px; text-align: center; color: #64748b; }
.ssc-skipped { margin: 10px 0 0; color: #94a3b8; font-size: 11px; }

.ssc-details { margin-top: 12px; }
.ssc-details__summary { cursor: pointer; color: #4f46e5; font-size: 12px; font-weight: 600; }
.ssc-list--passed { margin-top: 8px; }

@media (prefers-color-scheme: dark) {
    .ssc-panel { background: #0f172a; color: #e2e8f0; }
    .ssc-panel__foot { background: #111c33; border-top-color: #1e293b; }
    .ssc-verdict { background: #111c33; border-color: #1e293b; }
    .ssc-dial__inner { background: #0f172a; }
    .ssc-dial__score { color: #f8fafc; }
    .ssc-item { background: #111c33; }
    .ssc-item--high { background: #2a1216; }
    .ssc-item--medium { background: #2a2113; }
    .ssc-item--pass { background: #10231a; }
    .ssc-item__detail { color: #94a3b8; }
    .ssc-url { background: #1e1b4b; color: #c7d2fe; }
    .ssc-btn { background: #1e293b; color: #e2e8f0; border-color: #334155; }
    .ssc-clean { background: #10231a; color: #bbf7d0; }
    .ssc-cap { background: #2a1216; color: #fecaca; }
}

`;
