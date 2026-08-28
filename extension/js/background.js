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

/** Reports are kept in memory; the worker may be recycled, that is fine. */
const reports = new Map();

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.sync.get({showButton: true}, (prefs) => {
        chrome.storage.sync.set(prefs);
    });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message) { return false; }

    if (message.type === 'SSC_REPORT' && sender.tab) {
        reports.set(sender.tab.id, message.report);
        paintBadge(sender.tab.id, message.report);
        sendResponse({stored: true});
        return false;
    }

    if (message.type === 'SSC_LAST_REPORT') {
        sendResponse({report: reports.get(message.tabId) || null});
        return false;
    }

    return false;
});

function paintBadge(tabId, report) {
    const colour = BADGE_COLOURS[report.level] || '#64748b';
    chrome.action.setBadgeText({tabId, text: report.rating});
    chrome.action.setBadgeBackgroundColor({tabId, color: colour});
    chrome.action.setTitle({
        tabId,
        title: `Site Safety Checker\n${report.verdict} - score ${report.score}/100`
    });
}

/* A new page in the tab invalidates the old rating. */
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading' && changeInfo.url) {
        reports.delete(tabId);
        chrome.action.setBadgeText({tabId, text: ''});
    }
});

chrome.tabs.onRemoved.addListener((tabId) => reports.delete(tabId));
