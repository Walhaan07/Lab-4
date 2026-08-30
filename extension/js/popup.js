/*
 * popup.js -- toolbar popup.
 * Shows the rating of the active tab and can start a scan without using the
 * in-page button (useful when the button has been switched off).
 */
'use strict';

const $ = (id) => document.getElementById(id);
const LEVELS = ['safe', 'ok', 'caution', 'risky', 'danger'];

async function activeTab() {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    return tab;
}

function show(report) {
    $('result').hidden = false;
    $('grade').textContent = report.rating;
    $('grade').className = 'grade ' + (LEVELS.includes(report.level) ? report.level : '');
    $('verdict').textContent = `${report.verdict} · ${report.score}/100`;

    const failedCount = report.failedCount !== undefined ? report.failedCount : report.failed;
    $('detail').textContent = failedCount
        ? `${failedCount} of ${report.total} checks raised a finding`
        : `All ${report.total} checks passed`;
    $('checkCount').textContent = `${report.total} checks · reputation + heuristics`;

    const list = $('findings');
    list.replaceChildren();

    // A known address outranks anything the heuristics found.
    if (report.blocked && report.threat) {
        const li = document.createElement('li');
        li.className = 'high';
        li.textContent = `${report.threat.label} — recognised by ${report.threat.source}. Do not sign in or download here.`;
        list.appendChild(li);
    }

    // Why the wording checks stood down, when they did.
    if (report.context && report.context.userDriven) {
        const li = document.createElement('li');
        li.textContent = report.context.reason;
        list.appendChild(li);
    }

    if (Array.isArray(report.patterns)) {
        report.patterns.forEach((pattern) => {
            const li = document.createElement('li');
            li.className = 'high';
            li.textContent = `Pattern: ${pattern.title}. ${pattern.detail}`;
            list.appendChild(li);
        });
    }
    if (Array.isArray(report.failed)) {
        report.failed.slice(0, 5).forEach((check) => {
            const li = document.createElement('li');
            if (check.severity === 'high' || check.severity === 'medium') {
                li.className = check.severity;
            }
            li.textContent = `${check.title}: ${check.detail}`;
            list.appendChild(li);
        });
    }
}

function ask(tabId, message) {
    return new Promise((resolve) => {
        chrome.tabs.sendMessage(tabId, message, (response) => {
            void chrome.runtime.lastError;      // page without content script
            resolve(response);
        });
    });
}

(async function init() {
    const tab = await activeTab();
    $('url').textContent = tab && tab.url ? `You are on "${tab.url}"` : 'No page in this tab.';

    chrome.storage.sync.get({showButton: true}, (prefs) => {
        $('showButton').checked = prefs.showButton;
    });

    $('showButton').addEventListener('change', async (event) => {
        const visible = event.target.checked;
        chrome.storage.sync.set({showButton: visible});
        if (tab) { await ask(tab.id, {type: 'SSC_TOGGLE_BUTTON', visible}); }
    });

    $('run').addEventListener('click', async () => {
        if (!tab) { return; }
        $('verdict').textContent = 'Running the checks…';
        $('detail').textContent = 'One moment.';
        $('result').hidden = false;
        await ask(tab.id, {type: 'SSC_RUN'});
        window.setTimeout(async () => {
            const response = await ask(tab.id, {type: 'SSC_GET_REPORT'});
            if (response && response.report) { show(response.report); }
            else {
                $('verdict').textContent = 'This page cannot be checked';
                $('detail').textContent = 'Browsers block extensions on internal pages.';
            }
        }, 250);
    });

    if (tab) {
        const response = await ask(tab.id, {type: 'SSC_GET_REPORT'});
        if (response && response.report) { show(response.report); }
    }
}());
