/*
 * background.js -- MV3 service worker.
 *
 * Keeps the last safety report for each tab, paints the rating on the toolbar
 * icon badge, and clears the result when the tab navigates somewhere else.
 */
'use strict';

const BADGE_COLOURS = {
    safe: '#16a34a',
    ok: '#65a30d',
    caution: '#d97706',
    risky: '#ea580c',
    danger: '#dc2626'
};

/*
 * An MV3 service worker is stopped whenever it goes idle, which would throw
 * away anything held in a plain Map. Results are written to session storage
 * (cleared when the browser closes) with an in-memory cache in front of it, so
 * the popup still finds the last rating after the worker has been recycled.
 */
const cache = new Map();

async function saveReport(tabId, report) {
    cache.set(tabId, report);
    try {
        await chrome.storage.session.set({['tab-' + tabId]: report});
    } catch (e) {
        /* storage.session unavailable (older browser) - the cache still works */
    }
}

async function loadReport(tabId) {
    if (cache.has(tabId)) { return cache.get(tabId); }
    try {
        const stored = await chrome.storage.session.get('tab-' + tabId);
        const report = stored['tab-' + tabId] || null;
        if (report) { cache.set(tabId, report); }
        return report;
    } catch (e) {
        return null;
    }
}

async function forgetReport(tabId) {
    cache.delete(tabId);
    try {
        await chrome.storage.session.remove('tab-' + tabId);
    } catch (e) { /* ignore */ }
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.get({showButton: true}, (prefs) => {
        chrome.storage.sync.set(prefs);
    });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message) { return false; }

    if (message.type === 'SSC_REPORT' && sender.tab) {
        saveReport(sender.tab.id, message.report);
        paintBadge(sender.tab.id, message.report);
        sendResponse({stored: true});
        return false;
    }

    if (message.type === 'SSC_LAST_REPORT') {
        loadReport(message.tabId).then((report) => sendResponse({report}));
        return true;                       // reply arrives asynchronously
    }

    return false;
});

function paintBadge(tabId, report) {
    const colour = BADGE_COLOURS[report.level] || '#64748b';
    // The tab can disappear between the scan and the badge update.
    chrome.action.setBadgeText({tabId, text: report.rating}).catch(() => {});
    chrome.action.setBadgeBackgroundColor({tabId, color: colour}).catch(() => {});
    chrome.action.setTitle({
        tabId,
        title: `VeriSafe\n${report.verdict} - score ${report.score}/100`
    }).catch(() => {});
}

/* A new page in the tab invalidates the old rating. */
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading' && changeInfo.url) {
        forgetReport(tabId);
        chrome.action.setBadgeText({tabId, text: ''}).catch(() => {});
    }
});

chrome.tabs.onRemoved.addListener((tabId) => forgetReport(tabId));
