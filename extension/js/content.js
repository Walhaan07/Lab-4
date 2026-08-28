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
    var shadow = null;
    var elements = {};
    var lastReport = null;

    /* ------------------------------------------------------------- helpers */

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
        /* The host is pinned bottom-right inline as well as in the stylesheet:
           if the styles ever fail to apply, the button is still where the user
           expects it rather than trailing off the end of the page. */
        host.style.cssText = 'all: initial; position: fixed; right: 18px; bottom: 18px; ' +
                             'width: 0; height: 0; z-index: 2147483647;';
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
            '\nClick to run the spam / safety test (Alt+Shift+S)';
        button.setAttribute('aria-haspopup', 'dialog');

        var shield = el('span', 'ssc-button__icon', '🛡');
        var label = el('span', 'ssc-button__label');
        label.appendChild(el('span', 'ssc-button__lead', 'You are on '));
        label.appendChild(el('span', 'ssc-button__url', '"' + shortUrl(location.href) + '"'));

        var badge = el('span', 'ssc-button__badge');
        badge.hidden = true;

        button.appendChild(shield);
        button.appendChild(label);
        button.appendChild(badge);

        /* ---- Part 2: the report panel ------------------------------------ */
        var panel = el('section', 'ssc-panel');
        panel.hidden = true;
        panel.setAttribute('role', 'dialog');
        panel.setAttribute('aria-label', 'Site safety report');

        var header = el('header', 'ssc-panel__head');
        header.appendChild(el('h2', 'ssc-panel__title', 'Site safety report'));
        var close = el('button', 'ssc-panel__close', '×');
        close.type = 'button';
        close.title = 'Close (Esc)';
        header.appendChild(close);

        var body = el('div', 'ssc-panel__body');

        var footer = el('footer', 'ssc-panel__foot');
        var rerun = el('button', 'ssc-btn ssc-btn--ghost', 'Run tests again');
        rerun.type = 'button';
        var note = el('span', 'ssc-foot__note', 'Heuristic scan · no data leaves your browser');
        footer.appendChild(rerun);
        footer.appendChild(note);

        panel.appendChild(header);
        panel.appendChild(body);
        panel.appendChild(footer);

        shadow.appendChild(panel);
        shadow.appendChild(button);

        elements = {host: host, button: button, badge: badge, panel: panel, body: body};

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

    /* ------------------------------------------------------------ analysis */

    function runTests(force) {
        if (lastReport && !force) { return lastReport; }

        var testCount = (window.SpamAnalyzer && window.SpamAnalyzer.checks)
            ? window.SpamAnalyzer.checks.length : 0;
        elements.body.replaceChildren(el('p', 'ssc-loading',
            'Running ' + testCount + ' safety tests on this page…'));

        // Let the browser paint the "running" state before the sync scan.
        window.setTimeout(function () {
            var report;
            if (!window.SpamAnalyzer || typeof window.SpamAnalyzer.analyze !== 'function') {
                elements.body.replaceChildren(el('p', 'ssc-loading',
                    'The analyser did not load. Reload the extension and try again.'));
                return;
            }
            try {
                report = window.SpamAnalyzer.analyze({url: location.href, document: document});
            } catch (error) {
                elements.body.replaceChildren(el('p', 'ssc-loading', 'The scan failed: ' + error.message));
                return;
            }
            lastReport = report;
            renderReport(report);
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
                    failed: report.failed.length, total: report.totalTests,
                    analysedAt: report.analysedAt
                }
            }, function () { void chrome.runtime.lastError; });
        } catch (e) { /* extension context reloaded - ignore */ }
    }

    /* ------------------------------------------------------------ renderer */

    function renderReport(report) {
        var body = elements.body;
        body.replaceChildren();

        /* verdict block with the score dial */
        var verdict = el('div', 'ssc-verdict ssc-level--' + report.level);

        var dial = el('div', 'ssc-dial');
        dial.style.setProperty('--ssc-score', String(report.score));
        var dialInner = el('div', 'ssc-dial__inner');
        dialInner.appendChild(el('span', 'ssc-dial__score', String(report.score)));
        dialInner.appendChild(el('span', 'ssc-dial__max', '/ 100'));
        dial.appendChild(dialInner);

        var summary = el('div', 'ssc-verdict__text');
        summary.appendChild(el('span', 'ssc-verdict__grade', 'Rating ' + report.rating));
        summary.appendChild(el('strong', 'ssc-verdict__word', report.verdict));
        summary.appendChild(el('span', 'ssc-verdict__host', report.host || report.url));
        summary.appendChild(el('span', 'ssc-verdict__count',
            report.failed.length + ' of ' + report.totalTests + ' tests raised a warning'));

        verdict.appendChild(dial);
        verdict.appendChild(summary);
        body.appendChild(verdict);

        body.appendChild(el('p', 'ssc-url', 'You are on "' + report.url + '"'));

        if (report.cappedBy && report.cappedBy.length) {
            body.appendChild(el('p', 'ssc-cap',
                'The score is held at ' + report.scoreCap + ' or below because ' +
                report.cappedBy.length + ' finding(s) are conclusive on their own.'));
        }

        /* failed tests */
        if (report.failed.length) {
            body.appendChild(el('h3', 'ssc-section', 'Warnings'));
            var list = el('ul', 'ssc-list');
            report.failed.forEach(function (check) {
                var item = el('li', 'ssc-item ssc-item--' + check.severity);
                item.appendChild(el('span', 'ssc-item__points', '-' + check.points));
                var textWrap = el('div', 'ssc-item__text');
                textWrap.appendChild(el('span', 'ssc-item__title', check.title));
                textWrap.appendChild(el('span', 'ssc-item__detail', check.detail));
                item.appendChild(textWrap);
                list.appendChild(item);
            });
            body.appendChild(list);
        } else {
            body.appendChild(el('p', 'ssc-clean', 'No warning was raised by any of the ' +
                report.totalTests + ' tests.'));
        }

        /* passed tests, collapsed */
        var details = el('details', 'ssc-details');
        details.appendChild(el('summary', 'ssc-details__summary',
            'Tests passed (' + report.passed.length + ')'));
        var passedList = el('ul', 'ssc-list ssc-list--passed');
        report.passed.forEach(function (check) {
            var item = el('li', 'ssc-item ssc-item--pass');
            item.appendChild(el('span', 'ssc-item__points', '✓'));
            var wrap = el('div', 'ssc-item__text');
            wrap.appendChild(el('span', 'ssc-item__title', check.title));
            item.appendChild(wrap);
            passedList.appendChild(item);
        });
        details.appendChild(passedList);
        body.appendChild(details);

        if (report.skipped.length) {
            body.appendChild(el('p', 'ssc-skipped',
                report.skipped.length + ' test(s) could not run on this page.'));
        }
    }

    function updateBadge(report) {
        var badge = elements.badge;
        badge.hidden = false;
        badge.textContent = report.rating;
        badge.className = 'ssc-button__badge ssc-level--' + report.level;
        elements.button.classList.add('ssc-button--rated');
    }

    /* -------------------------------------------------------------- panel */

    function togglePanel() {
        if (elements.panel.hidden) {
            elements.panel.hidden = false;
            elements.button.setAttribute('aria-expanded', 'true');
            runTests(!lastReport);
            if (lastReport) { renderReport(lastReport); }
        } else {
            hidePanel();
        }
    }

    function hidePanel() {
        elements.panel.hidden = true;
        elements.button.setAttribute('aria-expanded', 'false');
    }

    /* ------------------------------------------- single page app navigation */

    /*
     * Many sites change the address without loading a new document, which
     * would leave the button showing a stale URL and a rating that belongs to
     * the previous view. Watch for that and reset.
     */
    function watchNavigation() {
        var current = location.href;

        var onChange = function () {
            if (location.href === current) { return; }
            current = location.href;
            lastReport = null;
            updateLabel();
            elements.badge.hidden = true;
            elements.button.classList.remove('ssc-button--rated');
            if (!elements.panel.hidden) { runTests(true); }
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
        if (label) { label.textContent = '"' + shortUrl(location.href) + '"'; }
        elements.button.title = 'You are on ' + location.href +
            '\nClick to run the spam / safety test (Alt+Shift+S)';
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

    function start() {
        buildUi();
        watchNavigation();
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
