/*
 * demo.js -- wiring for the NetBeans demo page.
 * Uses exactly the same analyser that the extension injects into web pages,
 * so the page works even when the extension is not installed.
 */
(function () {
    'use strict';

    var LEVEL_WORDS = {
        safe: 'safe', ok: 'ok', caution: 'caution', risky: 'risky', danger: 'danger'
    };

    var form = document.getElementById('url-form');
    var input = document.getElementById('url-input');
    var reportBox = document.getElementById('report');

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) { node.className = className; }
        if (text !== undefined) { node.textContent = text; }
        return node;
    }

    function render(report) {
        reportBox.hidden = false;
        reportBox.replaceChildren();
        reportBox.className = 'report level-' + (LEVEL_WORDS[report.level] || 'caution');

        if (report.error) {
            reportBox.appendChild(el('p', 'report__error', report.error));
            return;
        }

        var head = el('div', 'report__head');

        var dial = el('div', 'dial');
        dial.style.setProperty('--score', String(report.score));
        dial.appendChild(el('span', 'dial__value', String(report.score)));
        dial.appendChild(el('span', 'dial__max', '/100'));

        var text = el('div', 'report__summary');
        text.appendChild(el('span', 'grade', 'Rating ' + report.rating));
        text.appendChild(el('strong', 'verdict', report.verdict));
        text.appendChild(el('span', 'target', report.url));
        text.appendChild(el('span', 'count',
            report.failed.length + ' warning(s) · ' + report.passed.length + ' passed · ' +
            report.skipped.length + ' skipped · ' + report.totalTests + ' tests'));

        head.appendChild(dial);
        head.appendChild(text);
        reportBox.appendChild(head);

        if (report.failed.length) {
            reportBox.appendChild(el('h3', 'report__section', 'Warnings'));
            var list = el('ul', 'checks');
            report.failed.forEach(function (check) {
                var item = el('li', 'check check--' + check.severity);
                item.appendChild(el('span', 'check__points', '-' + check.points));
                var body = el('div', 'check__body');
                body.appendChild(el('span', 'check__title', check.title));
                body.appendChild(el('span', 'check__detail', check.detail));
                body.appendChild(el('span', 'check__meta', check.category + ' · test id: ' + check.id));
                item.appendChild(body);
                list.appendChild(item);
            });
            reportBox.appendChild(list);
        } else {
            reportBox.appendChild(el('p', 'report__clean', 'No warnings: every test that could run passed.'));
        }

        var details = el('details', 'report__details');
        details.appendChild(el('summary', null, 'Passed tests (' + report.passed.length + ')'));
        var passed = el('ul', 'checks checks--passed');
        report.passed.forEach(function (check) {
            var item = el('li', 'check check--pass');
            item.appendChild(el('span', 'check__points', '✓'));
            var body = el('div', 'check__body');
            body.appendChild(el('span', 'check__title', check.title));
            item.appendChild(body);
            passed.appendChild(item);
        });
        details.appendChild(passed);
        reportBox.appendChild(details);

        if (report.skipped.length) {
            var skipped = el('details', 'report__details');
            skipped.appendChild(el('summary', null,
                'Skipped tests (' + report.skipped.length + ') - these need the page content'));
            var skippedList = el('ul', 'checks checks--passed');
            report.skipped.forEach(function (check) {
                var item = el('li', 'check check--skip');
                item.appendChild(el('span', 'check__points', '–'));
                var body = el('div', 'check__body');
                body.appendChild(el('span', 'check__title', check.title));
                item.appendChild(body);
                skippedList.appendChild(item);
            });
            skipped.appendChild(skippedList);
            reportBox.appendChild(skipped);
        }

        reportBox.scrollIntoView({behavior: 'smooth', block: 'nearest'});
    }

    function testUrl(value) {
        var url = String(value || '').trim();
        if (!url) { return; }
        if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) { url = 'http://' + url; }
        render(window.SpamAnalyzer.analyze({url: url}));
    }

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        testUrl(input.value);
    });

    Array.prototype.forEach.call(document.querySelectorAll('.chip'), function (chip) {
        chip.addEventListener('click', function () {
            input.value = chip.getAttribute('data-url');
            testUrl(input.value);
        });
    });

    document.getElementById('scan-page').addEventListener('click', function () {
        render(window.SpamAnalyzer.analyze({url: location.href, document: document}));
    });
}());
