/*
 * content.js  --  Demo 4 (Lab 4), part 1 + part 2
 * ---------------------------------------------------------------------------
 * Injected into every page the browser visits.
 *
 * Part 1: embeds a button that displays   You are on "<URL>"
 * Part 2: pressing the button runs the spam / phishing tests from
 *         spam-analyzer.js and shows a safety rating for the site.
 *
 * The whole UI lives inside a shadow root so the host page CSS can never
 * break it, and so the extension never changes the layout of the page.
 * ---------------------------------------------------------------------------
 */
(function () {
    'use strict';

    // Only the top document, never inside frames, and never twice.
    if (window.top !== window.self) { return; }
    if (window.__siteSafetyCheckerLoaded) { return; }
    window.__siteSafetyCheckerLoaded = true;

    var HOST_ID = 'site-safety-checker-root';
    var DEFAULT_POSITION = {right: 18, bottom: 100};
    var TEST_COUNT = (window.SpamAnalyzer && window.SpamAnalyzer.checks)
        ? window.SpamAnalyzer.checks.length : 0;
    var DRAG_THRESHOLD = 4;             // px before a press counts as a drag
    var shadow = null;
    var elements = {};
    var lastReport = null;
    var renderedReport = null;          // what the panel is currently showing
    var position = {right: DEFAULT_POSITION.right, bottom: DEFAULT_POSITION.bottom};
    var positionIsUserChosen = false;   // a dragged position always wins
    var collapsed = false;              // pill shown as a circle
    var side = 'right';                 // which way the pill grows from its anchor
    var morphTimer = null;
    var morphDelay = null;              // an opening waiting for the toggle to arrive
    var orbit = null;                   // the toggle's trip around the pill
    var dragBase = null;                // where the anchor was when a drag began
    var morphing = false;               // the pill is between its two shapes
    var EDGE = 10;                      // closest the UI comes to a window edge
    var DOCK_GAP = 7;                   // matches the dock's CSS gap

    /* ------------------------------------------------------------- helpers */

    var SVG_NS = 'http://www.w3.org/2000/svg';

    /*
     * Inline SVG rather than emoji: an emoji is drawn by the operating system,
     * so the same button looks different on Windows, macOS and Linux, and it
     * cannot take the accent colour.
     */
    var ICON_PATHS = {
        shield: 'M12 2.6 4.6 5.7v5.5c0 4.4 3.1 8.5 7.4 9.6 4.3-1.1 7.4-5.2 7.4-9.6V5.7Z',
        shieldCheck: ['M12 2.6 4.6 5.7v5.5c0 4.4 3.1 8.5 7.4 9.6 4.3-1.1 7.4-5.2 7.4-9.6V5.7Z',
                      'm9 11.8 2.2 2.2 4-4.3'],
        close: ['M6 6l12 12', 'M18 6 6 18'],
        check: ['m5 12.5 4.5 4.5L19 7.5'],
        alert: ['M12 8.4v4.8', 'M12 16.5h.01',
                'M10.3 3.6 2.7 17a2 2 0 0 0 1.7 3h15.2a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0Z'],
        chevron: ['m9 6 6 6-6 6'],
        collapse: ['m13 6 6 6-6 6', 'm5 6 6 6-6 6'],
        refresh: ['M20 11.5A8 8 0 1 1 17.6 6', 'M20 4v5h-5']
    };

    function icon(name, strokeWidth) {
        var svg = document.createElementNS(SVG_NS, 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', String(strokeWidth || 1.9));
        svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round');
        svg.setAttribute('aria-hidden', 'true');
        var paths = ICON_PATHS[name];
        (typeof paths === 'string' ? [paths] : paths).forEach(function (d) {
            var path = document.createElementNS(SVG_NS, 'path');
            path.setAttribute('d', d);
            svg.appendChild(path);
        });
        return svg;
    }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) { node.className = className; }
        if (text !== undefined && text !== null) { node.textContent = text; }
        return node;
    }

    /** Shorten the URL so it fits on the button but stays recognisable. */
    function shortUrl(url, max) {
        max = max || 48;
        var pretty = url.replace(/^https?:\/\//, '').replace(/\/$/, '');
        if (pretty.length <= max) { return pretty; }
        return pretty.slice(0, max - 1) + '…';
    }

    /* ------------------------------------------------------------ building */

    function buildUi() {
        var host = document.createElement('div');
        host.id = HOST_ID;
        // The host element itself is styled inline: nothing on the page can
        // override these, and nothing here can leak onto the page.
        /*
         * The host is a zero-sized anchor box pinned to the viewport; the
         * button and the panel are positioned against it, so moving the host
         * is what moves the whole UI.
         *
         * It sits 100px up rather than flush with the bottom edge because many
         * sites put their own fixed bar there - a chat composer, a cookie
         * notice - and the button would cover it. The user can drag it
         * anywhere from there.
         *
         * `contain` matters as much as the rest of the line: without it the
         * pill changing width - the morph, the label folding - marks the page
         * behind it for layout too, and on a heavy site that is the difference
         * between an animation that runs on its own and one that waits for the
         * document. The box is already a fixed 0x0 anchor, so containing its
         * size and layout costs nothing; paint is deliberately left out, since
         * containing that would clip the UI to the anchor.
         */
        host.style.cssText = 'all: initial; position: fixed; ' +
                             'right: ' + DEFAULT_POSITION.right + 'px; ' +
                             'bottom: ' + DEFAULT_POSITION.bottom + 'px; ' +
                             'width: 0; height: 0; z-index: 2147483647; ' +
                             'contain: layout style size;';
        (document.body || document.documentElement).appendChild(host);

        shadow = host.attachShadow({mode: 'open'});

        /* The stylesheet is injected as text, not linked: a linked
           chrome-extension:// stylesheet is blocked on file:/// pages, which
           left the button unstyled and effectively invisible there. */
        var style = document.createElement('style');
        style.textContent = window.SSC_PANEL_CSS || '';
        shadow.appendChild(style);

        /* ---- Part 1: the embedded button --------------------------------- */
        var button = el('button', 'ssc-button');
        button.type = 'button';
        button.title = 'You are on ' + location.href +
            '\nClick to run the spam / safety test (Alt+Shift+S)' +
            '\nDrag the button to move it out of the way';
        button.setAttribute('aria-haspopup', 'dialog');

        var shield = el('span', 'ssc-button__mark');
        shield.appendChild(icon('shieldCheck'));
        var label = el('span', 'ssc-button__label');
        label.appendChild(el('span', 'ssc-button__lead', 'You are on'));
        label.appendChild(el('span', 'ssc-button__url', '"' + shortUrl(location.href) + '"'));

        var badge = el('span', 'ssc-button__badge');

        button.appendChild(shield);
        button.appendChild(label);
        button.appendChild(badge);

        /* A long address makes the pill wide, so it can be collapsed to a
           circle showing only the rating. The toggle sits beside the pill
           rather than inside it, so it stays reachable in both states. */
        var collapseToggle = el('button', 'ssc-dock__toggle');
        collapseToggle.type = 'button';
        collapseToggle.appendChild(icon('collapse'));   // rotated when collapsed
        collapseToggle.title = 'Minimise to a circle';
        collapseToggle.setAttribute('aria-label', 'Minimise the button to a circle');

        var dock = el('div', 'ssc-dock');
        dock.appendChild(collapseToggle);
        dock.appendChild(button);

        /* ---- Part 2: the report panel ------------------------------------ */
        var panel = el('section', 'ssc-panel');
        panel.hidden = true;
        panel.setAttribute('role', 'dialog');
        panel.setAttribute('aria-label', 'VeriSite report');

        var header = el('header', 'ssc-panel__head');

        var mark = el('span', 'ssc-panel__mark');
        mark.appendChild(icon('shield'));

        var heading = el('div', 'ssc-panel__heading');
        heading.appendChild(el('h2', 'ssc-panel__title', 'VeriSite report'));
        heading.appendChild(el('p', 'ssc-panel__subtitle', TEST_COUNT + ' checks · runs in this browser'));

        var close = el('button', 'ssc-icon-btn ssc-panel__close');
        close.type = 'button';
        close.title = 'Close (Esc)';
        close.setAttribute('aria-label', 'Close the report');
        close.appendChild(icon('close'));

        header.appendChild(mark);
        header.appendChild(heading);
        header.appendChild(close);

        var body = el('div', 'ssc-panel__body');
        body.setAttribute('aria-live', 'polite');

        var footer = el('footer', 'ssc-panel__foot');
        var rerun = el('button', 'ssc-btn');
        rerun.type = 'button';
        rerun.appendChild(icon('refresh'));
        rerun.appendChild(el('span', null, 'Rescan'));
        var note = el('span', 'ssc-foot__note', 'Heuristic scan · nothing leaves your browser');
        footer.appendChild(rerun);
        footer.appendChild(note);

        panel.appendChild(header);
        panel.appendChild(body);
        panel.appendChild(footer);

        shadow.appendChild(panel);
        shadow.appendChild(dock);

        elements = {host: host, dock: dock, button: button, badge: badge,
                    toggle: collapseToggle, panel: panel, body: body};

        /*
         * Bound here rather than in renderReport: the body outlives every
         * render, so binding it there left one more listener behind on each
         * open, and by the tenth the panel was being measured and placed ten
         * times for a single row opening.
         */
        body.addEventListener('toggle', function (event) {
            // Opening a check changes the height, so the panel is placed again.
            if (event.target && event.target.classList.contains('ssc-item__box')) { placePanel(); }
        }, true);
        // A wheel or a swipe during the jump animation hands the scroll back.
        body.addEventListener('wheel', stopScroll, {passive: true});
        body.addEventListener('touchstart', stopScroll, {passive: true});

        collapseToggle.addEventListener('click', function () { setCollapsed(!collapsed, true); });

        button.addEventListener('click', togglePanel);
        close.addEventListener('click', hidePanel);
        rerun.addEventListener('click', function () { runTests(true); });
        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape' && !panel.hidden) { hidePanel(); }
            // Alt+Shift+S opens the report without reaching for the mouse.
            if (event.altKey && event.shiftKey && (event.key === 'S' || event.key === 's')) {
                event.preventDefault();
                togglePanel();
            }
        });
    }

    /* ----------------------------------------------------------- which side */

    /*
     * The whole UI hangs off a zero-sized anchor. Everything to do with which
     * way it opens comes down to one question: is there room between that
     * anchor and the edge of the window for what is about to appear?
     *
     * The anchor is not the same edge on both sides - it is the dock's right
     * edge when the dock grows left, and its left edge when it grows right -
     * so everything below works in the dock's own box and converts to the
     * anchor at the last moment. Turning the side without re-deriving the
     * anchor was what threw the whole dock a full width across the window.
     */

    function anchorX() {
        return window.innerWidth - position.right;
    }

    function reducedMotion() {
        try {
            return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        } catch (e) {
            return false;
        }
    }

    function toggleWidth() { return elements.toggle.offsetWidth || 24; }
    function dockWidth() { return elements.dock.offsetWidth; }
    function dockHeight() { return elements.dock.offsetHeight; }

    /** Where the dock's left edge sits in the window. */
    function dockLeft(forSide, width) {
        if (width === undefined) { width = dockWidth(); }
        return (forSide || side) === 'left' ? anchorX() : anchorX() - width;
    }

    /** The anchor offset that puts a dock `width` wide with its left edge at `left`. */
    function rightForDockLeft(left, forSide, width) {
        if (width === undefined) { width = dockWidth(); }
        return window.innerWidth - ((forSide || side) === 'left' ? left : left + width);
    }

    /** Room between the anchor and the window edge, on either side. */
    function roomOn(which, x) {
        if (x === undefined) { x = anchorX(); }
        return Math.max(0, (which === 'right' ? x : window.innerWidth - x) - EDGE);
    }

    /*
     * How wide the dock wants to be with the whole address showing.
     *
     * Measuring it is a layout, so the answer is kept until something that
     * could change it happens - a new address, or a new window size.
     */
    var naturalWidth = 0;
    var naturalStale = true;

    function naturalDockWidth() {
        /*
         * Never measured while the pill is mid-morph. Measuring switches every
         * transition in the subtree off for a frame, and doing that to a
         * transition already running cancels it, leaving the pill snapped to
         * its target instead of arriving there. The last answer stands until
         * the shape has landed, which is why it is replaced rather than
         * emptied - there is always something sensible to answer with.
         */
        if ((naturalStale || !naturalWidth) && !morphing) {
            naturalWidth = measureButton(false, true).width + toggleWidth() + DOCK_GAP;
            naturalStale = false;
        }
        return Math.min(naturalWidth || dockWidth(), window.innerWidth - 2 * EDGE);
    }

    function forgetNaturalWidth() { naturalStale = true; }

    /**
     * Which way should a dock `width` wide, with its left edge at `left`, grow?
     *
     * The question is not whether the dock fits where it is - collapsed to a
     * circle it fits anywhere - but whether it would still fit once opened.
     * So the width tested is the one the pill wants when it is showing the
     * address, and the toggle turns round as soon as opening would run the
     * pill off the edge rather than only once the circle itself reaches it.
     *
     * Where both directions have room the current side keeps it, which is what
     * stops the toggle flapping while the pill is dragged across the middle of
     * a wide window.
     */
    function sideForBox(left, width, want) {
        if (width === undefined) { width = dockWidth(); }
        if (want === undefined) { want = naturalDockWidth(); }
        var fitsRight = (left + width) - want >= EDGE;                  // grows leftwards
        var fitsLeft = left + want <= window.innerWidth - EDGE;         // grows rightwards
        if (fitsRight && fitsLeft) {
            /* Parked hard against an edge, the dock anchors to that edge:
               folding to the circle then leaves it in the corner it was put
               in, instead of sliding a pill's width back into the page. */
            if (left <= EDGE + 1) { return 'left'; }
            if (left + width >= window.innerWidth - EDGE - 1) { return 'right'; }
            return side;
        }
        if (fitsRight) { return 'right'; }
        if (fitsLeft) { return 'left'; }
        // Neither direction can hold it: take the roomier one.
        return (left + width) > (window.innerWidth - left) ? 'right' : 'left';
    }

    /** Keeps a dock box of this size inside the window. */
    function clampBox(left, top, width, height) {
        return {
            left: clamp(left, EDGE, Math.max(EDGE, window.innerWidth - width - EDGE)),
            top: clamp(top, EDGE, Math.max(EDGE, window.innerHeight - height - EDGE))
        };
    }

    /*
     * The pill never grows past the room it has, however long the address is.
     * It is left alone during a drag: re-fitting on every pointer move made
     * the pill change width under the cursor, and the box is kept inside the
     * window by the drag itself.
     */
    function applyRoomLimit() {
        if (dragBase) { return; }
        var room = roomOn(side) - toggleWidth() - DOCK_GAP;
        elements.button.style.maxWidth = Math.max(120, Math.min(460, Math.round(room))) + 'px';
    }

    /* The chevrons point the way the pill will move when the toggle is pressed. */
    function updateToggleIcon() {
        var flipped = (side === 'right') === collapsed;
        elements.toggle.classList.toggle('ssc-dock__toggle--flipped', flipped);
        elements.toggle.title = collapsed ? 'Show the full address' : 'Minimise to a circle';
        elements.toggle.setAttribute('aria-label', elements.toggle.title);
    }

    /*
     * A spring, sampled rather than approximated.
     *
     * A cubic-bezier cannot overshoot and settle, and that settle is most of
     * what makes a movement feel like an object rather than a value being
     * interpolated. These are the two numbers SwiftUI uses: `response` is how
     * long the spring takes to cover the distance, `damping` how much of the
     * overshoot survives - below 1 it passes the target and comes back.
     *
     * @param {number} t seconds since the start
     * @returns {number} progress, 0 at the start, about 1 at rest, briefly over
     */
    function springAt(t, response, damping) {
        var omega = (2 * Math.PI) / response;
        if (damping < 1) {
            var damped = omega * Math.sqrt(1 - damping * damping);
            return 1 - Math.exp(-damping * omega * t) *
                (Math.cos(damped * t) + (damping * omega / damped) * Math.sin(damped * t));
        }
        return 1 - Math.exp(-omega * t) * (1 + omega * t);       // critically damped
    }

    /*
     * Moves the toggle round to the other side of the pill along the arc it
     * would trace if it were rolling around it, rather than jumping across.
     *
     * The path is a circle and the timing is a spring, sampled into keyframes
     * so the browser interpolates between points that already carry the
     * physics. It leaves quickly, arcs over the pill, and settles with a small
     * overshoot; it lifts a little in scale on the way, as something crossing
     * a gap does. The chevron inside turns under its own transition, so the
     * control arrives already pointing the new way.
     */
    function orbitToggle(from, to) {
        var toggle = elements.toggle;
        var dx = from.left - to.left;
        var dy = from.top - to.top;
        if (!Math.round(dx) && !Math.round(dy)) { return 0; }
        if (reducedMotion() || typeof toggle.animate !== 'function') { return 0; }

        var radius = Math.abs(dx) / 2;
        /*
         * A shallow arc, not a semicircle. The toggle's trip is as wide as the
         * pill - close to 400px - and lifting it by half of that threw it high
         * above the window rather than round the thing it belongs to. Held to
         * a fifth of the distance and capped, it skims the top of the pill at
         * any width.
         */
        var lift = clamp(Math.abs(dx) * 0.2, 14, 42);
        var direction = dx >= 0 ? 1 : -1;
        var centre = dx / 2;
        var duration = 520;
        var frames = [];
        var steps = 30;                     // dense enough that the samples read as a curve

        for (var i = 0; i <= steps; i++) {
            var t = i / steps;
            var progress = springAt(t * duration / 1000, 0.42, 0.78);
            /* The arc's height and the scale follow the un-overshot progress,
               so the lift cannot invert into a dip below the resting line;
               only the travel itself springs past and comes back. */
            var settled = clamp(progress, 0, 1);
            var angle = Math.PI * progress;
            var arc = Math.PI * settled;

            frames.push({
                offset: t,
                transform: 'translate(' +
                    (centre + direction * radius * Math.cos(angle)).toFixed(2) + 'px, ' +
                    (dy * (1 - progress) - lift * Math.sin(arc)).toFixed(2) + 'px) scale(' +
                    (1 + 0.09 * Math.sin(arc)).toFixed(3) + ')'
            });
        }
        // Land exactly where the layout puts it, whatever the last sample says.
        frames[frames.length - 1] = {offset: 1, transform: 'translate(0px, 0px) scale(1)'};

        if (orbit) { orbit.cancel(); }
        toggle.classList.add('ssc-dock__toggle--orbiting');
        /* Asked for before the animation starts, so the layer is ready for the
           first frame rather than being made during it. */
        toggle.style.willChange = 'transform';
        /* linear: the timing is already in the samples, and easing them a
           second time would flatten the spring back into a slide. */
        orbit = toggle.animate(frames, {duration: duration, easing: 'linear', fill: 'none'});
        /* Cancelling fires asynchronously, so a second flip started while the
           first was still running would otherwise have the old animation's
           handler tidy up after the new one. */
        var mine = orbit;
        mine.onfinish = mine.oncancel = function () {
            if (orbit !== mine) { return; }
            toggle.classList.remove('ssc-dock__toggle--orbiting');
            toggle.style.willChange = '';
            orbit = null;
        };
        return duration;
    }

    /**
     * Move the dock to the other side of its anchor.
     * @returns {number} how long the move takes, so a caller can wait for it
     */
    function setSide(next, animate) {
        if (next === side) { applyRoomLimit(); return 0; }

        var before = elements.toggle.getBoundingClientRect();
        var width = dockWidth();
        var left = dockLeft(side, width);        // where the dock is, before the turn

        side = next;
        elements.dock.classList.toggle('ssc-dock--left', side === 'left');
        /*
         * The anchor swaps ends with the side, so leaving it alone moved the
         * dock a full width sideways - the jump that looked like the pill
         * running away from the cursor and parking itself near the middle of
         * the window. Deriving the anchor back from the box it already
         * occupies means nothing moves but the toggle.
         */
        setPosition({right: rightForDockLeft(left, side, width), bottom: position.bottom});
        applyRoomLimit();
        updateToggleIcon();
        var after = elements.toggle.getBoundingClientRect();

        var duration = animate === false ? 0 : orbitToggle(before, after);
        if (!elements.panel.hidden) { placePanel(); }
        return duration;
    }

    /** Puts the dock back inside the window after a drag, resize or restore. */
    function settleInsideWindow() {
        var width = dockWidth();
        var height = dockHeight();
        var box = clampBox(dockLeft(side, width),
                           window.innerHeight - position.bottom - height, width, height);

        setSide(sideForBox(box.left, width), false);
        setPosition({
            right: rightForDockLeft(box.left, side, width),
            bottom: window.innerHeight - (box.top + height)
        });
        applyRoomLimit();
    }

    /* ------------------------------------------------------------ analysis */

    /*
     * Runs the checks. When `quiet` is set the panel is left closed and only
     * the pill and the toolbar badge are updated - that is what happens
     * automatically on every page, so the verdict is already coloured when you
     * arrive rather than after you press the button.
     */
    function runTests(force, quiet) {
        if (lastReport && !force) { return lastReport; }

        if (!quiet) {
            var loading = el('p', 'ssc-loading');
            loading.appendChild(el('span', 'ssc-spinner'));
            loading.appendChild(el('span', null, 'Running ' + TEST_COUNT + ' checks on this page…'));
            elements.body.replaceChildren(loading);
        }

        // Let the browser paint the "running" state before the sync scan.
        window.setTimeout(function () {
            var report;
            if (!window.SpamAnalyzer || typeof window.SpamAnalyzer.analyze !== 'function') {
                if (!quiet) {
                    elements.body.replaceChildren(el('p', 'ssc-loading',
                        'The analyser did not load. Reload the extension and try again.'));
                }
                return;
            }
            try {
                report = window.SpamAnalyzer.analyze({url: location.href, document: document});
            } catch (error) {
                if (!quiet) {
                    elements.body.replaceChildren(el('p', 'ssc-loading', 'The scan failed: ' + error.message));
                }
                return;
            }
            lastReport = report;
            if (!quiet || !elements.panel.hidden) { renderReport(report); }
            updateBadge(report);
            publish(report);
        }, 30);
    }

    function publish(report) {
        try {
            chrome.runtime.sendMessage({
                type: 'SSC_REPORT',
                report: {
                    url: report.url, score: report.score, rating: report.rating,
                    verdict: report.verdict, level: report.level,
                    blocked: report.blocked, threat: report.threat,
                    patterns: report.patterns.length,
                    failed: report.failed.length, total: report.totalTests,
                    analysedAt: report.analysedAt
                }
            }, function () { void chrome.runtime.lastError; });
        } catch (e) { /* extension context reloaded - ignore */ }
    }

    /* ------------------------------------------------------------ renderer */

    /* An SVG ring rather than a conic gradient: round line caps, a clean edge
       at any score, and the sweep can be animated from empty. */
    function buildRing(report) {
        var RADIUS = 36;
        var circumference = 2 * Math.PI * RADIUS;

        var wrap = el('div', 'ssc-ring');
        var svg = document.createElementNS(SVG_NS, 'svg');
        svg.setAttribute('class', 'ssc-ring__svg');
        svg.setAttribute('viewBox', '0 0 84 84');
        svg.setAttribute('aria-hidden', 'true');

        /* The arc is painted with the same gradient as the button, so the
           score and the pill read as one result. The id only has to be unique
           inside this shadow root. */
        var gradientId = 'ssc-arc-gradient';
        var defs = document.createElementNS(SVG_NS, 'defs');
        var gradient = document.createElementNS(SVG_NS, 'linearGradient');
        gradient.setAttribute('id', gradientId);
        gradient.setAttribute('x1', '0'); gradient.setAttribute('y1', '0');
        gradient.setAttribute('x2', '1'); gradient.setAttribute('y2', '1');
        [['0%', 'var(--ssc-ring-1, var(--ssc-arc-1, var(--ssc-level)))'],
         ['52%', 'var(--ssc-ring-2, var(--ssc-arc-2, var(--ssc-level)))'],
         ['100%', 'var(--ssc-ring-3, var(--ssc-arc-3, var(--ssc-level)))']].forEach(function (pair) {
            var stop = document.createElementNS(SVG_NS, 'stop');
            stop.setAttribute('offset', pair[0]);
            stop.style.stopColor = pair[1];
            gradient.appendChild(stop);
        });
        defs.appendChild(gradient);
        svg.appendChild(defs);

        ['ssc-ring__track', 'ssc-ring__arc'].forEach(function (className) {
            var circle = document.createElementNS(SVG_NS, 'circle');
            circle.setAttribute('class', className);
            circle.setAttribute('cx', '42');
            circle.setAttribute('cy', '42');
            circle.setAttribute('r', String(RADIUS));
            svg.appendChild(circle);
        });

        var arc = svg.querySelector('.ssc-ring__arc');
        /* Inline style, not a presentation attribute: the stylesheet's own
           stroke rule would otherwise win and the gradient be ignored. That
           rule stays as the fallback if the gradient cannot be resolved. */
        arc.style.stroke = 'url(#' + gradientId + ')';
        arc.style.strokeDasharray = circumference + ' ' + circumference;
        arc.style.strokeDashoffset = String(circumference);   // start empty
        window.requestAnimationFrame(function () {
            window.requestAnimationFrame(function () {
                arc.style.strokeDashoffset = String(circumference * (1 - report.score / 100));
            });
        });

        var value = el('div', 'ssc-ring__value');
        value.appendChild(el('span', 'ssc-ring__score', String(report.score)));
        value.appendChild(el('span', 'ssc-ring__max', '/ 100'));

        wrap.appendChild(svg);
        wrap.appendChild(value);
        return wrap;
    }

    /*
     * Counts by severity, so the shape of the result is readable at a glance.
     * Each one is a button that jumps to the first check of that kind, which
     * matters on a page like the sample where sixteen findings do not fit on
     * screen at once.
     */
    function buildTally(report) {
        var counts = {high: 0, medium: 0, low: 0};
        report.failed.forEach(function (check) { counts[check.severity]++; });

        var tally = el('div', 'ssc-tally');
        [
            {key: 'high', label: 'high', value: counts.high, colour: 'var(--ssc-danger)'},
            {key: 'medium', label: 'medium', value: counts.medium, colour: 'var(--ssc-caution)'},
            {key: 'low', label: 'low', value: counts.low, colour: 'var(--ssc-text-3)'},
            {key: 'pass', label: 'passed', value: report.passed.length, colour: 'var(--ssc-safe)'}
        ].forEach(function (entry) {
            if (!entry.value) { return; }
            var item = el('button', 'ssc-tally__item');
            item.type = 'button';
            item.title = 'Jump to the ' + entry.label + ' checks';
            var dot = el('span', 'ssc-tally__dot');
            dot.style.setProperty('--ssc-dot', entry.colour);
            item.appendChild(dot);
            item.appendChild(el('b', null, String(entry.value)));
            item.appendChild(el('span', null, entry.label));
            item.addEventListener('click', function () { jumpToGroup(entry.key); });
            item.style.setProperty('--i', String(tally.children.length));
            tally.appendChild(item);
        });
        return tally;
    }

    /** Scrolls the report to the first check of a given severity. */
    function jumpToGroup(key) {
        var disclosure = elements.body.querySelector('.ssc-disclosure');

        if (key === 'pass' && disclosure && !disclosure.open) {
            disclosure.open = true;
            /*
             * Opening the fold adds every passed check at once. Measuring in
             * the same turn asked where a row was before the browser had
             * placed it, so the scroll set off towards a target that then
             * moved - which is the stutter the jump had. One frame's wait
             * costs nothing and the answer is then the real one.
             */
            window.requestAnimationFrame(function () { scrollToGroup(key); });
            return;
        }
        scrollToGroup(key);
    }

    /*
     * How far a row sits down the scrolling box, in layout terms.
     *
     * A rect would be measured through whatever transform the row's entrance
     * animation is part way through, and the offsets have to be walked rather
     * than read once: an ancestor being animated carries a transform of its
     * own, and that makes it the offset parent for everything inside it.
     */
    function offsetWithin(node, container) {
        var y = 0;
        while (node && node !== container) {
            y += node.offsetTop;
            node = node.offsetParent;
        }
        return node === container ? y : null;
    }

    function scrollToGroup(key) {
        var body = elements.body;
        var target = body.querySelector('.ssc-item--' + key);
        if (!target) { return; }

        var top = offsetWithin(target, body);
        if (top === null) {                     // nothing to walk up: measure it
            top = body.scrollTop +
                  target.getBoundingClientRect().top - body.getBoundingClientRect().top;
        }
        smoothScroll(body, top - 8);

        target.classList.add('ssc-item--flash');
        window.setTimeout(function () { target.classList.remove('ssc-item--flash'); }, 1300);
    }

    /*
     * The report's own scroll, rather than scrollTo({behavior: 'smooth'}).
     *
     * The native one is driven from the compositor and re-aims itself as the
     * content around it settles, which is exactly the moment this is used -
     * seventy rows have just been revealed. A short ease run here knows where
     * it is going from the first frame and takes a fixed time to get there.
     */
    var scrollFrame = 0;

    function stopScroll() {
        if (scrollFrame) { window.cancelAnimationFrame(scrollFrame); scrollFrame = 0; }
    }

    function smoothScroll(node, to) {
        var from = node.scrollTop;
        to = clamp(to, 0, Math.max(0, node.scrollHeight - node.clientHeight));
        var delta = to - from;

        stopScroll();
        if (!delta) { return; }
        if (reducedMotion()) { node.scrollTop = to; return; }

        /* Longer for a longer trip, the way a sheet does, but bounded so a
           hundred checks never make it feel slow. */
        var duration = clamp(200 + Math.abs(delta) * 0.5, 260, 560);
        var began = 0;

        var step = function (now) {
            if (!began) { began = now; }
            var t = clamp((now - began) / duration, 0, 1);
            // quick away, long settle - the panel's own curve, in one dimension
            node.scrollTop = from + delta * (1 - Math.pow(1 - t, 4));
            scrollFrame = t < 1 ? window.requestAnimationFrame(step) : 0;
        };
        scrollFrame = window.requestAnimationFrame(step);
    }

    /*
     * Every check is a <details>: the row shows what was found, and opening it
     * explains what the check looks for and why it matters. <details> is used
     * rather than a click handler so it works with the keyboard and with a
     * screen reader without any extra wiring.
     */
    function buildCheckItem(check, options) {
        options = options || {};
        var item = el('li', 'ssc-item ssc-item--' + (options.severity || check.severity));
        var box = el('details', 'ssc-item__box');
        var summary = el('summary', 'ssc-item__summary');

        summary.appendChild(el('span', 'ssc-item__dot'));

        var text = el('div', 'ssc-item__text');
        var row = el('div', 'ssc-item__row');
        row.appendChild(el('span', 'ssc-item__title', check.title));
        if (options.showPoints) {
            row.appendChild(el('span', 'ssc-item__points', '\u2212' + check.points));
        }
        text.appendChild(row);
        if (options.showDetail && check.detail && check.detail !== 'OK') {
            text.appendChild(el('p', 'ssc-item__detail', check.detail));
        }
        summary.appendChild(text);

        var chevron = icon('chevron');
        chevron.setAttribute('class', 'ssc-item__chevron');
        summary.appendChild(chevron);

        box.appendChild(summary);

        var about = el('div', 'ssc-item__about');
        about.appendChild(el('p', null, check.about || 'No further detail is available for this check.'));
        box.appendChild(about);

        item.appendChild(box);
        return item;
    }

    function renderReport(report) {
        var body = elements.body;
        stopScroll();
        body.replaceChildren();

        /* A recognised threat is not a matter of degree - it goes first, above
           the score, because the score is no longer the interesting part. */
        if (report.blocked && report.threat) {
            var threat = el('div', 'ssc-threat');
            threat.appendChild(icon('alert'));
            var threatText = el('div', 'ssc-threat__text');
            threatText.appendChild(el('span', 'ssc-threat__title', report.verdict));
            threatText.appendChild(el('span', 'ssc-threat__body',
                report.threat.label + '. ' + report.threat.detail));
            threatText.appendChild(el('span', 'ssc-threat__source',
                'Recognised by: ' + report.threat.source + ' · do not sign in or download anything here.'));
            threat.appendChild(threatText);
            body.appendChild(threat);
        }

        /* verdict */
        var summary = el('div', 'ssc-summary ssc-level--' + report.level);
        summary.appendChild(buildRing(report));

        var text = el('div', 'ssc-summary__text');
        text.appendChild(el('span', 'ssc-chip', 'Rating ' + report.rating));
        text.appendChild(el('strong', 'ssc-summary__verdict', report.verdict));
        text.appendChild(el('span', 'ssc-summary__host', report.host || report.url));
        summary.appendChild(text);
        body.appendChild(summary);

        body.appendChild(buildTally(report));
        body.appendChild(el('p', 'ssc-url', 'You are on "' + report.url + '"'));

        if (report.cappedBy && report.cappedBy.length) {
            var cap = el('div', 'ssc-cap');
            cap.appendChild(icon('alert'));
            cap.appendChild(el('span', null,
                'The score is held at ' + report.scoreCap + ' or below: ' +
                report.cappedBy.length + ' finding(s) are conclusive on their own.'));
            body.appendChild(cap);
        }

        /* Why the wording tests were left out - the words here are not the
           site's own, and saying so is more useful than a silent skip. */
        if (report.context && report.context.userDriven) {
            var note = el('div', 'ssc-note');
            note.appendChild(icon('check'));
            note.appendChild(el('span', null, report.context.reason));
            body.appendChild(note);
        }

        /* Findings that only mean something in combination. */
        if (report.patterns && report.patterns.length) {
            var patternSection = el('section', 'ssc-section');
            var patternTitle = el('h3', 'ssc-section__title');
            patternTitle.appendChild(el('span', null, 'Attack patterns recognised'));
            patternTitle.appendChild(el('span', 'ssc-count', String(report.patterns.length)));
            patternSection.appendChild(patternTitle);
            report.patterns.forEach(function (pattern) {
                var box = el('div', 'ssc-pattern');
                box.appendChild(el('strong', 'ssc-pattern__title', pattern.title));
                box.appendChild(el('span', 'ssc-pattern__body', pattern.about));
                box.appendChild(el('span', 'ssc-pattern__evidence', pattern.detail));
                patternSection.appendChild(box);
            });
            body.appendChild(patternSection);
        }

        /* findings */
        if (report.failed.length) {
            var section = el('section', 'ssc-section');
            var title = el('h3', 'ssc-section__title');
            title.appendChild(el('span', null, 'Findings'));
            title.appendChild(el('span', 'ssc-count', String(report.failed.length)));
            section.appendChild(title);

            var list = el('ul', 'ssc-list');
            report.failed.forEach(function (check, index) {
                var item = buildCheckItem(check, {showPoints: true, showDetail: true});
                // capped so a long list still finishes quickly
                item.style.setProperty('--i', String(Math.min(index, 9)));
                list.appendChild(item);
            });
            section.appendChild(list);
            body.appendChild(section);
        } else {
            var clean = el('div', 'ssc-clean');
            var iconWrap = el('span', 'ssc-clean__icon');
            iconWrap.appendChild(icon('check', 2.4));
            clean.appendChild(iconWrap);
            var cleanText = el('div', 'ssc-clean__text');
            cleanText.appendChild(el('span', 'ssc-clean__title', 'Nothing to report'));
            cleanText.appendChild(el('span', 'ssc-clean__note',
                'All ' + report.passed.length + ' checks that could run on this page passed.'));
            clean.appendChild(cleanText);
            body.appendChild(clean);
        }

        /* passed tests, folded away */
        if (report.passed.length) {
            var details = el('details', 'ssc-disclosure');
            var disclosure = el('summary', 'ssc-disclosure__summary');
            var chevron = icon('chevron');
            chevron.setAttribute('class', 'ssc-disclosure__chevron');
            disclosure.appendChild(chevron);
            disclosure.appendChild(el('span', null, 'Checks passed (' + report.passed.length + ')'));
            details.appendChild(disclosure);

            var passedList = el('ul', 'ssc-list');
            report.passed.forEach(function (check, index) {
                var item = buildCheckItem(check, {severity: 'pass'});
                item.style.setProperty('--i', String(Math.min(index, 9)));
                passedList.appendChild(item);
            });
            details.appendChild(passedList);
            body.appendChild(details);
        }

        if (report.skipped.length) {
            body.appendChild(el('p', 'ssc-skipped',
                report.skipped.length + ' check(s) could not run on this page.'));
        }

        renderedReport = report;
        placePanel();          // the content just changed the panel's height
    }

    var LEVEL_CLASSES = ['ssc-level--safe', 'ssc-level--ok', 'ssc-level--caution',
                         'ssc-level--risky', 'ssc-level--danger'];

    /* classList rather than className: the drag handler also owns a class on
       this element, and replacing the whole attribute would drop it. */
    function setButtonLevel(level) {
        var button = elements.button;
        LEVEL_CLASSES.forEach(function (name) { button.classList.remove(name); });
        if (level) {
            button.classList.add('ssc-button--rated', 'ssc-level--' + level);
        } else {
            button.classList.remove('ssc-button--rated');
        }
    }

    function updateBadge(report) {
        var badge = elements.badge;
        var appearing = !elements.button.classList.contains('ssc-button--has-rating');
        badge.textContent = report.rating;
        badge.className = 'ssc-button__badge ssc-level--' + report.level;
        if (appearing) {
            // a small pop the first time a rating lands on the pill
            badge.classList.add('ssc-button__badge--pop');
            badge.addEventListener('animationend', function drop() {
                badge.removeEventListener('animationend', drop);
                badge.classList.remove('ssc-button__badge--pop');
            });
        }
        badge.title = report.verdict + ' - ' + report.score + '/100';
        elements.button.classList.add('ssc-button--has-rating');
        setButtonLevel(report.level);
    }

    /* -------------------------------------------------------------- panel */

    /*
     * Decide which way the report opens.
     *
     * The measurements are taken against the host anchor and the panel's own
     * size, not the button's edges: the button grows with the length of the
     * URL, so using its left edge flipped the panel to the wrong side on a
     * narrow window and pushed it off screen. The height is then capped to the
     * space actually available, so the panel can never overflow the viewport
     * however far the button has been dragged.
     */
    function placePanel() {
        var panel = elements.panel;
        panel.classList.remove('ssc-panel--below', 'ssc-panel--left');
        panel.style.maxHeight = '';
        panel.style.top = '';
        panel.style.bottom = '';
        panel.style.left = '';
        panel.style.right = '';

        var MARGIN = 12;                // breathing room against the window edge
        var anchor = elements.host.getBoundingClientRect();   // zero-sized corner
        var button = elements.button.getBoundingClientRect();
        // Measured from the button rather than hard coded, so the panel keeps
        // its distance if the button's size ever changes.
        var gap = Math.round(button.height) + 9;
        /*
         * offsetWidth/offsetHeight, not getBoundingClientRect: the panel's
         * entrance animation starts at scale(.98), and a rect measured mid
         * animation reported the panel ~8px narrower than it really is, which
         * was enough to skip the flip and leave it hanging off the edge.
         */
        var width = panel.offsetWidth || 384;
        var height = panel.offsetHeight || 420;

        /* ---- above or below ---- */
        var roomAbove = (anchor.bottom - gap) - MARGIN;
        var roomBelow = window.innerHeight - (anchor.top + gap) - MARGIN;
        var openBelow = roomAbove < height && roomBelow > roomAbove;
        panel.classList.toggle('ssc-panel--below', openBelow);

        if (openBelow) {
            panel.style.top = gap + 'px';
            panel.style.bottom = 'auto';
        } else {
            panel.style.bottom = gap + 'px';
            panel.style.top = 'auto';
        }

        var room = openBelow ? roomBelow : roomAbove;
        var ceiling = Math.min(640, window.innerHeight - 24);
        panel.style.maxHeight = Math.round(clamp(room, Math.min(200, ceiling), ceiling)) + 'px';

        /*
         * ---- which side ----
         * The report opens the same way the pill does, so the two read as one
         * object. Then it is pulled back inside the window: on a narrow screen
         * neither side has room for a 384px panel, and "flip it" would only
         * move the overflow from one edge to the other.
         */
        var wanted = side === 'left' ? anchor.left : anchor.right - width;
        var left = clamp(wanted, MARGIN, Math.max(MARGIN, window.innerWidth - width - MARGIN));
        panel.classList.toggle('ssc-panel--left', side === 'left');
        panel.classList.add('ssc-panel--pinned');
        panel.style.left = Math.round(left - anchor.left) + 'px';
        panel.style.right = 'auto';

        setPanelOrigin();
    }

    /*
     * Anchors the report's growth to the middle of the button, so it appears to
     * come out of whatever the button currently is - the full pill or the
     * collapsed circle - and drop back into it on the way out. Measured from
     * the live boxes rather than fixed to a corner, so it follows the button
     * after a drag or a collapse without any special cases.
     */
    function setPanelOrigin() {
        var panel = elements.panel;
        if (!panel.offsetWidth) { return; }

        /*
         * Offset geometry, not getBoundingClientRect: the entrance animation
         * fills backwards, so the panel already carries scale(.72) by the time
         * this runs and a measured rect would be the shrunken one. offsetLeft
         * and friends report the layout box and ignore transforms.
         *
         * The panel's offset parent is the host; the button sits inside the
         * dock, which is positioned, so its offsets are added together.
         */
        var buttonX = elements.dock.offsetLeft + elements.button.offsetLeft;
        var buttonY = elements.dock.offsetTop + elements.button.offsetTop;
        var ox = buttonX + elements.button.offsetWidth / 2 - panel.offsetLeft;
        var oy = buttonY + elements.button.offsetHeight / 2 - panel.offsetTop;
        panel.style.transformOrigin = Math.round(ox) + 'px ' + Math.round(oy) + 'px';
    }

    function togglePanel() {
        var closing = elements.panel.classList.contains('ssc-panel--closing');
        if (elements.panel.hidden || closing) {
            // re-opening during the exit: drop the exit and play the entrance
            window.clearTimeout(closeTimer);
            elements.panel.classList.remove('ssc-panel--closing');
            elements.panel.hidden = false;
            placePanel();
            elements.button.setAttribute('aria-expanded', 'true');
            /*
             * The page was already scanned on arrival, so this usually has
             * nothing to do. Rebuilding the hundred rows anyway put a long
             * synchronous stretch in the same frame as the opening animation,
             * and the first third of that animation was dropped.
             */
            if (!lastReport) { runTests(true); }
            else if (renderedReport !== lastReport) { renderReport(lastReport); }
        } else {
            hidePanel();
        }
    }

    /*
     * Closing plays an exit animation first. The panel keeps its box until the
     * animation ends, so the class is removed and `hidden` set in the same
     * callback; a guard covers the case where the animation never fires (a
     * background tab, or reduced motion turning it off).
     */
    function hidePanel() {
        var panel = elements.panel;
        elements.button.setAttribute('aria-expanded', 'false');
        if (panel.hidden || panel.classList.contains('ssc-panel--closing')) { return; }

        var finish = function (event) {
            /* animationend bubbles: the staggered rows inside the panel each
               fire one, and closing while they are still arriving would
               otherwise hide the panel before its own exit had played. */
            if (event && (event.target !== panel || event.animationName !== 'ssc-out')) { return; }
            window.clearTimeout(closeTimer);
            panel.removeEventListener('animationend', finish);
            panel.classList.remove('ssc-panel--closing');
            panel.hidden = true;
        };

        setPanelOrigin();                 // the button may have moved or changed shape
        panel.classList.add('ssc-panel--closing');
        panel.addEventListener('animationend', finish);
        closeTimer = window.setTimeout(finish, 520);
    }

    /* ---------------------------------------------------------- collapsing */

    /**
     * Collapsed, the pill becomes a circle showing just the rating letter.
     * @param {boolean} next   whether to collapse
     * @param {boolean} save   whether to remember the choice
     */
    /*
     * Morphs the pill between its two shapes. The width and height are
     * measured in both states and animated between them, because a transition
     * cannot interpolate from a content-driven size to a fixed one - the
     * element would simply jump.
     */
    /**
     * What size would the pill be in the other shape?
     *
     * Measured with the target class applied and every transition in the
     * subtree switched off, then put straight back. The label folds with its
     * own max-width transition, so measuring while that was still running
     * reported the collapsed width for an expand and the pill snapped at the
     * end instead of arriving.
     *
     * @param {boolean} mini     the shape to measure
     * @param {boolean} natural  ignore the room limit, to ask how wide it wants to be
     */
    function measureButton(mini, natural) {
        var button = elements.button;
        var wasMini = button.classList.contains('ssc-button--mini');
        var width = button.style.width;
        var height = button.style.height;
        var limit = button.style.maxWidth;

        button.classList.add('ssc-measuring');
        button.classList.toggle('ssc-button--mini', mini);
        /* Clear the inline size rather than setting it to auto: the circle
           takes its 46px from the stylesheet, and "auto" overrode that, so the
           morph was aiming at the content width - about 11px - and only
           reached 46 afterwards when the inline value was dropped. */
        button.style.width = '';
        button.style.height = '';
        if (natural) { button.style.maxWidth = '460px'; }
        var box = button.getBoundingClientRect();

        button.classList.toggle('ssc-button--mini', wasMini);
        button.style.width = width;
        button.style.height = height;
        button.style.maxWidth = limit;
        void button.offsetWidth;                                 // flush
        button.classList.remove('ssc-measuring');
        return {width: box.width, height: box.height};
    }

    function morphButton(toMini) {
        var button = elements.button;
        /* The laid-out size, not a measured rect: the pill carries a transform
           of its own while it is pressed or hovered, and starting the morph
           from a scaled rect made it jolt on the first frame. */
        var start = {width: button.offsetWidth, height: button.offsetHeight};
        var end = measureButton(toMini);

        morphing = true;
        button.style.width = start.width + 'px';
        button.style.height = start.height + 'px';
        void button.offsetWidth;                                 // flush

        /*
         * The spring is only used for growth. Overshooting a shrink means
         * passing below the target - collapsing 383px to 46px dipped to 2px
         * and sprang back, which reads as a glitch rather than a bounce.
         */
        button.style.transitionTimingFunction = toMini
            ? 'cubic-bezier(.32, .72, 0, 1)'
            : 'cubic-bezier(.32, 1.26, .5, 1)';

        window.requestAnimationFrame(function () {
            button.classList.toggle('ssc-button--mini', toMini);
            button.style.width = end.width + 'px';
            button.style.height = end.height + 'px';
        });

        var done = function (event) {
            // transitionend fires per property; only the width settles the shape
            if (event && (event.target !== button || event.propertyName !== 'width')) { return; }
            window.clearTimeout(morphTimer);
            button.removeEventListener('transitionend', done);
            morphing = false;
            // hand the size back to the stylesheet once it has arrived
            button.style.width = '';
            button.style.height = '';
            button.style.transitionTimingFunction = '';
        };
        button.addEventListener('transitionend', done);
        window.clearTimeout(morphTimer);
        morphTimer = window.setTimeout(done, 780);
    }

    function setCollapsed(next, save, instant) {
        collapsed = !!next;

        /*
         * Opening needs room. Ask how wide the pill wants to be, and if the
         * side it is parked on cannot hold it, send the toggle round the arc
         * to the other side first - then the pill opens into the window
         * instead of off the edge of it. The two overlap slightly, so it reads
         * as one movement rather than two.
         */
        window.clearTimeout(morphDelay);
        morphDelay = null;

        var travel = 0;
        if (!instant) {
            /* Both directions are re-checked, not just the opening one: after
               a collapse the circle may sit where the pill could no longer
               open, and the toggle should already be pointing the way it will
               go before it is pressed. */
            travel = setSide(sideForBox(dockLeft(), dockWidth(), naturalDockWidth()), true);
        }
        applyRoomLimit();
        updateToggleIcon();

        if (instant) {
            elements.button.classList.toggle('ssc-button--mini', collapsed);
            /* The remembered shape and the remembered corner come back from
               storage separately, so the side is settled here against the box
               the circle actually ends up in rather than the pill's. */
            settleInsideWindow();
        } else if (travel) {
            var shape = collapsed;
            morphDelay = window.setTimeout(function () {
                morphDelay = null;
                morphButton(shape);
            }, Math.round(travel * 0.55));
        } else {
            morphButton(collapsed);
        }
        updateLabel();

        /* Minimising takes the whole thing down to the circle, report
           included - leaving an open panel above a collapsed pill would be a
           strange half state. */
        if (collapsed) { hidePanel(); }
        else if (!elements.panel.hidden) { placePanel(); }
        if (save) {
            try {
                chrome.storage.local.set({buttonCollapsed: collapsed}, function () {
                    void chrome.runtime.lastError;
                });
            } catch (e) { /* storage unavailable - lasts for this page */ }
        }
    }

    function restoreCollapsed() {
        try {
            chrome.storage.local.get({buttonCollapsed: false}, function (stored) {
                if (stored && stored.buttonCollapsed) { setCollapsed(true, false, true); }
            });
        } catch (e) { /* storage unavailable - stay expanded */ }
    }

    /* ------------------------------------------------- avoiding page furniture */

    /*
     * Chat apps, cookie notices and support widgets pin their own bar to the
     * bottom of the window, and no fixed default can clear all of them. Rather
     * than guess a larger number, look at what is actually painted at the
     * bottom of this page: probe the point where the button would sit, walk up
     * to the first fixed or sticky element, and settle just above it.
     *
     * elementsFromPoint keeps this to a couple of hit tests instead of walking
     * the whole document.
     */
    function bottomBarTop() {
        if (!document.elementsFromPoint) { return null; }
        var x = clamp(window.innerWidth - 60, 1, window.innerWidth - 1);
        var probes = [window.innerHeight - 4, window.innerHeight - 28];
        var highest = null;

        probes.forEach(function (y) {
            var stack;
            try {
                stack = document.elementsFromPoint(x, y) || [];
            } catch (e) {
                return;
            }
            for (var i = 0; i < stack.length; i++) {
                var node = stack[i];
                if (node === elements.host || node === document.body ||
                    node === document.documentElement) { continue; }
                var style;
                try {
                    style = window.getComputedStyle(node);
                } catch (e) {
                    continue;
                }
                if (style.position !== 'fixed' && style.position !== 'sticky') { continue; }
                var box = node.getBoundingClientRect();
                // A bar along the bottom edge, not a full page overlay.
                if (box.height > 0 && box.height < window.innerHeight * 0.5 &&
                    box.bottom > window.innerHeight - 8) {
                    highest = highest === null ? box.top : Math.min(highest, box.top);
                }
                break;                      // the topmost painted layer is enough
            }
        });
        return highest;
    }

    function avoidBottomBar() {
        if (positionIsUserChosen) { return; }
        var top = bottomBarTop();
        if (top === null) { return; }
        var wanted = clamp(window.innerHeight - top + 12, DEFAULT_POSITION.bottom, 320);
        if (Math.abs(wanted - position.bottom) > 2) {
            setPosition({right: position.right, bottom: wanted});
        }
    }

    /* ------------------------------------------------------------ dragging */

    /*
     * The button can be dragged out of the way: pages put their own fixed
     * furniture in every corner, so no single default suits every site. The
     * chosen corner is remembered for next time.
     */
    function makeDraggable() {
        var button = elements.button;
        var drag = null;

        /*
         * One move per frame.
         *
         * A pointer reports far more often than the screen refreshes - more
         * again on a high rate trackpad - and the moves in between are work
         * nothing ever shows. The last position is recorded and the geometry
         * is done once, in the frame that is about to be painted.
         */
        function apply() {
            if (!drag) { return; }
            drag.frame = 0;

            var box = clampBox(drag.x - drag.grabX, drag.y - drag.grabY, drag.width, drag.height);

            /*
             * The side is settled from the box the dock now occupies, and the
             * anchor is then derived back from that same box, so turning it
             * moves the toggle round the pill and nothing else. It is settled
             * against the width the pill wants when it is open, not the width
             * it happens to have: dragging the collapsed circle towards an
             * edge turns the toggle round as soon as opening there would run
             * off the side, rather than at the edge itself.
             */
            var wanted = sideForBox(box.left, drag.width, drag.want);
            if (wanted !== side) { setSide(wanted, true); }

            setPosition({
                right: rightForDockLeft(box.left, side, drag.width),
                bottom: window.innerHeight - (box.top + drag.height)
            });
        }

        function schedule() {
            if (drag && !drag.frame) { drag.frame = window.requestAnimationFrame(apply); }
        }

        button.addEventListener('pointerdown', function (event) {
            if (event.button !== 0) { return; }
            var dock = elements.dock.getBoundingClientRect();
            drag = {
                /* Where inside the dock it was taken hold of. Tracking that
                   rather than the anchor is what keeps the pill under the
                   cursor when the side turns. */
                grabX: event.clientX - dock.left,
                grabY: event.clientY - dock.top,
                width: dock.width,
                height: dock.height,
                want: naturalDockWidth(),
                x: event.clientX,
                y: event.clientY,
                fromX: event.clientX,
                fromY: event.clientY,
                moved: false,
                frame: 0
            };
            button.setPointerCapture(event.pointerId);
        });

        button.addEventListener('pointermove', function (event) {
            if (!drag) { return; }
            drag.x = event.clientX;
            drag.y = event.clientY;

            if (!drag.moved) {
                if (Math.abs(event.clientX - drag.fromX) +
                    Math.abs(event.clientY - drag.fromY) < DRAG_THRESHOLD) { return; }
                drag.moved = true;
                button.classList.add('ssc-button--dragging');
                hidePanel();
                beginDragMove();
            }
            schedule();
        });

        var finish = function (event) {
            if (!drag) { return; }
            var wasDrag = drag.moved;
            if (drag.frame) { window.cancelAnimationFrame(drag.frame); }
            drag = null;
            button.classList.remove('ssc-button--dragging');
            try { button.releasePointerCapture(event.pointerId); } catch (e) { /* already gone */ }
            if (!wasDrag) { return; }

            endDragMove();
            settleInsideWindow();          // the pill may want its full width back here
            positionIsUserChosen = true;
            savePosition();
            // Swallow the click that follows the drag.
            button.addEventListener('click', function stop(clickEvent) {
                clickEvent.stopImmediatePropagation();
                button.removeEventListener('click', stop, true);
            }, true);
        };

        button.addEventListener('pointerup', finish);
        button.addEventListener('pointercancel', finish);

        /*
         * Keep the button on screen when the window is resized - once per
         * frame. A window being dragged by its corner fires resize far faster
         * than the screen refreshes, and each of these measures the dock, the
         * panel and what the page has painted along its bottom edge.
         */
        var resizeFrame = 0;
        window.addEventListener('resize', function () {
            if (resizeFrame) { return; }
            resizeFrame = window.requestAnimationFrame(function () {
                resizeFrame = 0;
                forgetNaturalWidth();      // a narrower window caps how wide the pill may open
                settleInsideWindow();
                avoidBottomBar();
                if (!elements.panel.hidden) { placePanel(); }
            });
        });
    }

    function clamp(value, low, high) {
        return Math.min(high, Math.max(low, value));
    }

    /*
     * While the pill is being dragged the anchor moves with a transform rather
     * than by writing `right` and `bottom`. Both describe the same place, but
     * one is a composited move and the other is a layout of the page behind
     * it every frame, which is what turned a drag into a series of steps.
     */
    function beginDragMove() {
        dragBase = {right: position.right, bottom: position.bottom};
        elements.host.style.willChange = 'transform';
    }

    function endDragMove() {
        if (!dragBase) { return; }
        dragBase = null;
        /* Cleared and committed in the same write, so there is no frame in
           which the offsets have moved but the transform has not. */
        elements.host.style.transform = '';
        elements.host.style.willChange = '';
        setPosition(position);
    }

    function setPosition(next) {
        position = next;
        if (dragBase) {
            elements.host.style.transform =
                'translate3d(' + Math.round(dragBase.right - next.right) + 'px, ' +
                                 Math.round(dragBase.bottom - next.bottom) + 'px, 0)';
            return;
        }
        elements.host.style.right = Math.round(next.right) + 'px';
        elements.host.style.bottom = Math.round(next.bottom) + 'px';
    }

    /*
     * What is remembered is the dock's box, not the anchor: the anchor means a
     * different edge on each side, so a corner saved while the pill was parked
     * on the left came back a full width away from where it was left. Both
     * edges are kept, and the one the dock was parked against is the one it is
     * put back against, so it stays in its corner whatever size the window is
     * next time.
     */
    function savePosition() {
        var width = dockWidth();
        var left = dockLeft(side, width);
        try {
            chrome.storage.local.set({buttonPosition: {
                side: side,
                left: Math.round(left),
                right: Math.round(window.innerWidth - left - width),
                bottom: Math.round(position.bottom)
            }}, function () { void chrome.runtime.lastError; });
        } catch (e) { /* storage unavailable - the position lasts for this page */ }
    }

    function restorePosition() {
        try {
            chrome.storage.local.get({buttonPosition: null}, function (stored) {
                var saved = stored && stored.buttonPosition;
                if (!saved || typeof saved.bottom !== 'number') {
                    avoidBottomBar();       // no saved corner: fit around this page
                    return;
                }
                positionIsUserChosen = true;

                var width = dockWidth();
                var left;
                if (typeof saved.side === 'string' && typeof saved.left === 'number' &&
                    typeof saved.right === 'number') {
                    left = saved.side === 'left'
                        ? saved.left                                  // parked against the left
                        : window.innerWidth - saved.right - width;    // parked against the right
                } else if (typeof saved.right === 'number') {
                    /* Written by version 5 and earlier, where the number was
                       the anchor. Read it as one; the next drag rewrites it. */
                    left = (window.innerWidth - saved.right) - (side === 'left' ? 0 : width);
                } else {
                    avoidBottomBar();
                    return;
                }
                setPosition({
                    right: rightForDockLeft(left, side, width),
                    bottom: saved.bottom
                });
                settleInsideWindow();     // the window may be a different size now
            });
        } catch (e) { /* storage unavailable - keep the default corner */ }
    }

    /* ------------------------------------------- single page app navigation */

    /*
     * Many sites change the address without loading a new document, which
     * would leave the button showing a stale URL and a rating that belongs to
     * the previous view. Watch for that and reset.
     */
    var rescanTimer = null;
    var closeTimer = null;

    function watchNavigation() {
        var current = location.href;

        var onChange = function () {
            if (location.href === current) { return; }
            current = location.href;
            lastReport = null;
            updateLabel();
            elements.button.classList.remove('ssc-button--has-rating');
            setButtonLevel(null);
            // Re-scan the new view so the pill recolours by itself.
            window.clearTimeout(rescanTimer);
            rescanTimer = window.setTimeout(function () {
                runTests(true, elements.panel.hidden);
            }, 500);
        };

        window.addEventListener('popstate', onChange);
        window.addEventListener('hashchange', onChange);

        ['pushState', 'replaceState'].forEach(function (name) {
            var original = history[name];
            if (typeof original !== 'function') { return; }
            history[name] = function () {
                var result = original.apply(this, arguments);
                window.setTimeout(onChange, 0);
                return result;
            };
        });

        // Belt and braces: some routers change the URL in ways the hooks miss.
        window.setInterval(onChange, 1500);
    }

    function updateLabel() {
        var label = shadow.querySelector('.ssc-button__url');
        var text = '"' + shortUrl(location.href) + '"';
        if (label && label.textContent !== text) {
            label.textContent = text;
            forgetNaturalWidth();       // a different address is a different width
        }
        elements.button.title = 'You are on ' + location.href +
            '\nClick for the safety report (Alt+Shift+S)' +
            '\nDrag to move it out of the way';
    }

    /* ------------------------------------------------- popup / preferences */

    function applyVisibility(visible) {
        if (elements.host) { elements.host.style.display = visible ? '' : 'none'; }
    }

    try {
        chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
            if (message && message.type === 'SSC_GET_REPORT') {
                if (!lastReport) { runTests(true); }
                sendResponse({report: lastReport ? {
                    url: lastReport.url, score: lastReport.score, rating: lastReport.rating,
                    verdict: lastReport.verdict, level: lastReport.level,
                    blocked: lastReport.blocked, threat: lastReport.threat,
                    patterns: lastReport.patterns,
                    context: lastReport.context,
                    failed: lastReport.failed.slice(0, 6), total: lastReport.totalTests,
                    failedCount: lastReport.failed.length
                } : null});
                return true;
            }
            if (message && message.type === 'SSC_RUN') {
                lastReport = null;
                elements.panel.hidden = false;
                runTests(true);
                sendResponse({ok: true});
            }
            if (message && message.type === 'SSC_TOGGLE_BUTTON') {
                applyVisibility(message.visible);
                sendResponse({ok: true});
            }
            return false;
        });
    } catch (e) { /* running outside the extension - demo page mode */ }

    /* --------------------------------------------------------------- start */

    /*
     * An administrator - or a student testing the extension - can add
     * addresses of their own without editing the code. They are read once at
     * start-up and handed to the reputation layer.
     */
    function loadLocalBlockList(done) {
        try {
            chrome.storage.local.get({blockList: []}, function (stored) {
                void chrome.runtime.lastError;
                if (stored && stored.blockList && stored.blockList.length &&
                    window.SpamAnalyzer && window.SpamAnalyzer.addThreatEntries) {
                    window.SpamAnalyzer.addThreatEntries(stored.blockList);
                }
                done();
            });
        } catch (e) {
            done();          // running outside the extension - demo page mode
        }
    }

    function start() {
        buildUi();
        makeDraggable();
        settleInsideWindow();       // decides the opening side for the default corner
        restorePosition();
        restoreCollapsed();
        /* Bars that appear a moment after load (cookie notices, chat widgets)
           are picked up by this second look. */
        window.setTimeout(avoidBottomBar, 1200);
        watchNavigation();

        /* Scan on arrival so the pill already shows the verdict. The short
           delay lets the page finish drawing, since half the checks read the
           rendered document. */
        window.setTimeout(function () {
            loadLocalBlockList(function () { runTests(true, true); });
        }, 500);
        try {
            chrome.storage.sync.get({showButton: true}, function (prefs) {
                applyVisibility(prefs.showButton);
            });
        } catch (e) { /* storage unavailable */ }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
}());
