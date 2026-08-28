/* ------------------------------------------------------------------
 * GENERATED FILE - do not edit.
 * Copied from src/spam-analyzer.js by "npm run sync".
 * ------------------------------------------------------------------ */
/*
 * spam-analyzer.js  --  Demo 4 (Lab 4)
 * ---------------------------------------------------------------------------
 * Heuristic spam / phishing analyser.
 *
 * The same engine is used in three places:
 *   1. the browser extension content script  (window.SpamAnalyzer)
 *   2. the NetBeans HTML5 demo page          (window.SpamAnalyzer)
 *   3. the Node.js unit tests                (require('./spam-analyzer'))
 *
 * It performs 32 independent tests. Every test that "hits" adds penalty points;
 * the safety score is 100 minus the accumulated penalty (clamped to 0..100).
 *
 * NOTE: this is a client side heuristic scanner written for a lab exercise.
 * It never contacts a remote blocklist, so it can produce false positives and
 * must not be treated as real anti-phishing protection.
 * ---------------------------------------------------------------------------
 */
(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();               // Node.js / NetBeans tests
    } else {
        root.SpamAnalyzer = factory();            // browser + extension
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /* ---------------------------------------------------------------- data */

    // Free / heavily abused top level domains.
    var SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
        'loan', 'download', 'review', 'country', 'stream', 'gdn', 'mom',
        'racing', 'win', 'bid', 'trade', 'date', 'faith', 'cricket', 'party',
        'science', 'accountant', 'zip', 'mov', 'rest', 'buzz', 'cam'
    ];

    // URL shorteners hide the real destination.
    var SHORTENERS = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
        'adf.ly', 'bit.do', 'cutt.ly', 'shorte.st', 'rb.gy', 'rebrand.ly',
        'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae', 'v.gd', 'x.co', 'shorturl.at'
    ];

    // Brands that phishing pages love to imitate.
    var BRANDS = [
        'paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook',
        'google', 'gmail', 'facebook', 'instagram', 'whatsapp', 'netflix',
        'amazon', 'ebay', 'dhl', 'fedex', 'ups', 'hsbc', 'barclays', 'chase',
        'wellsfargo', 'citibank', 'santander', 'revolut', 'binance', 'coinbase',
        'metamask', 'blockchain', 'steam', 'roblox', 'linkedin', 'dropbox'
    ];

    // Words that belong to a credential harvesting flow.
    var SENSITIVE_WORDS = [
        'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification',
        'secure', 'security', 'account', 'update', 'confirm', 'password',
        'credential', 'billing', 'invoice', 'payment', 'wallet', 'unlock',
        'suspended', 'recover', 'authenticate', 'webscr'
    ];

    // Classic unsolicited-advertising / scam phrases.
    var SPAM_PHRASES = [
        'you have won', 'you won', 'congratulations you', 'claim your prize',
        'free gift', 'free money', 'risk free', 'act now', 'limited time offer',
        'click here now', 'order now', 'buy now', 'lowest price', 'cheap meds',
        'work from home', 'make money fast', 'earn extra cash', 'double your',
        'no credit check', 'pre-approved', 'miracle cure', 'lose weight fast',
        'viagra', 'casino bonus', 'crypto giveaway', 'investment opportunity',
        'wire transfer', 'western union', 'bank transfer fee', 'nigerian',
        'inheritance fund', 'unclaimed funds', 'winner selected', 'gift card',
        'this is not a scam', '100% free', 'guaranteed income', 'hot singles',
        'increase your traffic', 'seo services', 'bulk email', 'weight loss pill'
    ];

    // Tokens that normally appear in obfuscated / packed scripts.
    var OBFUSCATION_TOKENS = [
        'eval(', 'atob(', 'unescape(', 'String.fromCharCode', 'document.write(',
        'new Function(', '\\x6', '\\u00'
    ];

    // Fake urgency wording.
    var URGENCY_PHRASES = [
        'expires in', 'offer ends', 'hurry', 'only a few left', 'last chance',
        'ends today', 'countdown', 'seconds remaining', 'act fast', 'while stocks last'
    ];

    // A page that collects 40% of the available penalty weight scores zero.
    var RISK_SPAN = 0.4;

    var EXECUTABLE_EXT = ['.exe', '.msi', '.apk', '.scr', '.bat', '.cmd', '.jar', '.dmg', '.vbs', '.ps1'];

    // Second level labels that are part of the public suffix (co.uk, com.au ...)
    var SECOND_LEVEL = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'mil', 'sch'];

    /* ------------------------------------------------------------- helpers */

    function parseUrl(url) {
        try {
            return new URL(url);
        } catch (e) {
            return null;
        }
    }

    function isIpHost(host) {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
            return host.split('.').every(function (o) { return Number(o) <= 255; });
        }
        return /^\[[0-9a-f:]+\]$/i.test(host);   // IPv6 literal
    }

    /** Best effort "registrable domain" (example.co.uk -> example.co.uk). */
    function registrableDomain(host) {
        var parts = String(host).toLowerCase().replace(/^\[|\]$/g, '').split('.');
        if (parts.length <= 2) { return parts.join('.'); }
        if (SECOND_LEVEL.indexOf(parts[parts.length - 2]) !== -1 && parts[parts.length - 1].length <= 3) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    }

    function subdomainLabels(host) {
        var full = String(host).toLowerCase().split('.');
        var reg = registrableDomain(host).split('.');
        return full.slice(0, Math.max(0, full.length - reg.length));
    }

    function countOccurrences(haystack, needles) {
        var found = [];
        for (var i = 0; i < needles.length; i++) {
            if (haystack.indexOf(needles[i]) !== -1) { found.push(needles[i]); }
        }
        return found;
    }

    function clamp(n, lo, hi) { return Math.min(hi, Math.max(lo, n)); }

    function short(text, max) {
        text = String(text).replace(/\s+/g, ' ').trim();
        return text.length > max ? text.slice(0, max - 1) + '…' : text;
    }

    /** Visible text of the page, capped so huge pages stay fast. */
    function visibleText(doc) {
        var body = doc && doc.body;
        if (!body) { return ''; }
        return (body.innerText || body.textContent || '').slice(0, 200000);
    }

    function sameSite(hostA, hostB) {
        return registrableDomain(hostA) === registrableDomain(hostB);
    }

    function elementStyle(doc, el) {
        try {
            var view = doc.defaultView || (typeof window !== 'undefined' ? window : null);
            return view && view.getComputedStyle ? view.getComputedStyle(el) : null;
        } catch (e) {
            return null;
        }
    }

    /* -------------------------------------------------------------- checks */
    /*
     * Every check returns:
     *    null      -> the test passed (nothing suspicious found)
     *    string    -> the test failed, the string is the evidence shown to user
     *    {detail, points} -> failed with a scaled penalty
     *
     * `weight` is the maximum penalty the test can add to the risk total.
     */
    var CHECKS = [

        /* ---------------------------- URL / transport level tests (1 - 16) */
        {
            id: 'https',
            title: 'Encrypted connection (HTTPS)',
            failTitle: 'Connection is not encrypted',
            category: 'Transport',
            weight: 12,
            run: function (c) {
                if (c.url.protocol === 'https:') { return null; }
                if (c.url.protocol === 'file:') { return null; }
                return 'The page is served over ' + c.url.protocol + ' so traffic is not encrypted.';
            }
        },
        {
            id: 'ip-host',
            title: 'Host name instead of raw IP address',
            failTitle: 'Site is addressed by a raw IP address',
            category: 'URL',
            weight: 12,
            run: function (c) {
                return isIpHost(c.host)
                    ? 'The site is addressed by the raw IP ' + c.host + ' instead of a domain name.'
                    : null;
            }
        },
        {
            id: 'punycode',
            title: 'No look-alike (punycode) characters in the domain',
            failTitle: 'Domain uses look-alike (punycode) characters',
            category: 'URL',
            weight: 10,
            run: function (c) {
                return c.host.indexOf('xn--') !== -1
                    ? 'The domain uses punycode (' + c.host + ') which can imitate another brand.'
                    : null;
            }
        },
        {
            id: 'at-symbol',
            title: 'No "@" trick in the address',
            failTitle: 'Address uses the "@" trick',
            category: 'URL',
            weight: 10,
            run: function (c) {
                var beforePath = c.href.split(/[?#]/)[0];
                return beforePath.indexOf('@') !== -1
                    ? 'The URL contains "@"; everything before it is ignored by the browser and can hide the real host.'
                    : null;
            }
        },
        {
            id: 'shortener',
            title: 'Destination is not hidden behind a URL shortener',
            failTitle: 'Destination is hidden behind a URL shortener',
            category: 'URL',
            weight: 6,
            run: function (c) {
                return SHORTENERS.indexOf(c.domain) !== -1
                    ? c.domain + ' is a URL shortener, the real destination is unknown.'
                    : null;
            }
        },
        {
            id: 'suspicious-tld',
            title: 'Top level domain has a good reputation',
            failTitle: 'Top level domain is frequently abused',
            category: 'URL',
            weight: 8,
            run: function (c) {
                var tld = c.host.split('.').pop();
                return SUSPICIOUS_TLDS.indexOf(tld) !== -1
                    ? '".' + tld + '" is a free / frequently abused top level domain.'
                    : null;
            }
        },
        {
            id: 'brand-impersonation',
            title: 'No brand name used outside the real domain',
            failTitle: 'Brand name used outside the real domain',
            category: 'URL',
            weight: 12,
            run: function (c) {
                var outside = (subdomainLabels(c.host).join('.') + ' ' + c.url.pathname).toLowerCase();
                var hits = countOccurrences(outside, BRANDS).filter(function (brand) {
                    return c.domain.indexOf(brand) === -1;   // brand not in the real domain
                });
                return hits.length
                    ? 'The address mentions "' + hits.join('", "') + '" but the real domain is ' + c.domain + '.'
                    : null;
            }
        },
        {
            id: 'many-subdomains',
            title: 'Reasonable number of sub-domains',
            failTitle: 'Too many sub-domain levels',
            category: 'URL',
            weight: 5,
            run: function (c) {
                var labels = subdomainLabels(c.host);
                return labels.length > 3
                    ? 'The host has ' + labels.length + ' sub-domain levels (' + c.host + ').'
                    : null;
            }
        },
        {
            id: 'long-url',
            title: 'Address is not abnormally long',
            failTitle: 'Address is abnormally long',
            category: 'URL',
            weight: 4,
            run: function (c) {
                return c.href.length > 100
                    ? 'The URL is ' + c.href.length + ' characters long; long URLs are used to hide the real target.'
                    : null;
            }
        },
        {
            id: 'hyphen-domain',
            title: 'Domain does not look typo-squatted',
            failTitle: 'Domain looks typo-squatted',
            category: 'URL',
            weight: 4,
            run: function (c) {
                var hyphens = (c.domain.match(/-/g) || []).length;
                return hyphens >= 3
                    ? 'The domain contains ' + hyphens + ' hyphens, a common typo-squatting pattern.'
                    : null;
            }
        },
        {
            id: 'digits-in-domain',
            title: 'Domain is not made of random digits',
            failTitle: 'Domain is padded with digits',
            category: 'URL',
            weight: 5,
            run: function (c) {
                if (isIpHost(c.host)) { return null; }        // already reported
                var digits = (c.domain.match(/\d/g) || []).length;
                return (digits >= 5 || digits / Math.max(1, c.domain.length) > 0.3)
                    ? 'The domain "' + c.domain + '" contains ' + digits + ' digits.'
                    : null;
            }
        },
        {
            id: 'sensitive-keywords',
            title: 'No credential-harvesting keywords in the address',
            failTitle: 'Credential-harvesting keywords in the address',
            category: 'URL',
            weight: 6,
            run: function (c) {
                var target = (c.host + c.url.pathname + c.url.search).toLowerCase();
                var hits = countOccurrences(target, SENSITIVE_WORDS);
                return hits.length >= 2
                    ? 'The address contains "' + hits.slice(0, 4).join('", "') + '".'
                    : null;
            }
        },
        {
            id: 'nonstandard-port',
            title: 'Standard web port',
            failTitle: 'Unusual network port',
            category: 'Transport',
            weight: 5,
            run: function (c) {
                if (!c.url.port) { return null; }
                var ok = ['80', '443', '8080', '8000', '8383', '3000', '5000'];
                return ok.indexOf(c.url.port) === -1
                    ? 'The site is served from the unusual port ' + c.url.port + '.'
                    : null;
            }
        },
        {
            id: 'encoded-chars',
            title: 'Address is not heavily percent-encoded',
            failTitle: 'Address is heavily percent-encoded',
            category: 'URL',
            weight: 4,
            run: function (c) {
                var encoded = (c.href.match(/%[0-9a-f]{2}/gi) || []).length;
                return encoded >= 6
                    ? 'The URL contains ' + encoded + ' percent-encoded characters, often used to obfuscate it.'
                    : null;
            }
        },
        {
            id: 'query-complexity',
            title: 'Simple query string',
            failTitle: 'Unusually complex query string',
            category: 'URL',
            weight: 3,
            run: function (c) {
                var params = c.url.search ? c.url.search.replace(/^\?/, '').split('&').length : 0;
                return params > 6
                    ? 'The URL carries ' + params + ' query parameters.'
                    : null;
            }
        },
        {
            id: 'executable-url',
            title: 'Address does not point at an executable file',
            failTitle: 'Address points at an executable file',
            category: 'URL',
            weight: 10,
            run: function (c) {
                var path = c.url.pathname.toLowerCase();
                var hit = EXECUTABLE_EXT.filter(function (ext) { return path.indexOf(ext) === path.length - ext.length && path.length > ext.length; });
                return hit.length
                    ? 'The URL points directly at a "' + hit[0] + '" file.'
                    : null;
            }
        },

        /* -------------------------------- page content tests (17 - 32) */
        {
            id: 'insecure-password-form',
            title: 'Passwords are not requested over an insecure page',
            failTitle: 'Password requested over an insecure page',
            category: 'Forms',
            needsDom: true,
            weight: 15,
            run: function (c) {
                var pw = c.doc.querySelectorAll('input[type="password"]').length;
                if (!pw) { return null; }
                if (c.url.protocol === 'https:' || c.url.protocol === 'file:') { return null; }
                return 'The page asks for a password (' + pw + ' field(s)) but is not using HTTPS.';
            }
        },
        {
            id: 'cross-domain-form',
            title: 'Forms submit to this same site',
            failTitle: 'Form submits your data to another site',
            category: 'Forms',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var bad = [];
                Array.prototype.forEach.call(c.doc.querySelectorAll('form[action]'), function (f) {
                    var action = f.getAttribute('action');
                    if (!action || action.charAt(0) === '#' || action.indexOf('javascript:') === 0) { return; }
                    var target;
                    try { target = new URL(action, c.href); } catch (e) { return; }
                    if (target.protocol === 'http:' && c.url.protocol === 'https:') {
                        bad.push(target.host + ' (unencrypted)');
                    } else if (target.host && !sameSite(target.host, c.host)) {
                        bad.push(target.host);
                    }
                });
                return bad.length
                    ? 'A form on this page posts your data to ' + bad.slice(0, 3).join(', ') + '.'
                    : null;
            }
        },
        {
            id: 'hidden-iframes',
            title: 'No hidden / zero-sized frames',
            failTitle: 'Hidden / zero-sized frames',
            category: 'Content',
            needsDom: true,
            weight: 8,
            run: function (c) {
                var hidden = 0;
                Array.prototype.forEach.call(c.doc.querySelectorAll('iframe'), function (f) {
                    var r = f.getBoundingClientRect ? f.getBoundingClientRect() : {width: 1, height: 1};
                    var st = elementStyle(c.doc, f);
                    var invisible = (st && (st.display === 'none' || st.visibility === 'hidden' || Number(st.opacity) === 0));
                    if (invisible || r.width <= 2 || r.height <= 2) { hidden++; }
                });
                return hidden
                    ? hidden + ' hidden frame(s) are loaded in the background (clickjacking / tracking pattern).'
                    : null;
            }
        },
        {
            id: 'third-party-scripts',
            title: 'Few third party scripts',
            failTitle: 'Many third party scripts',
            category: 'Content',
            needsDom: true,
            weight: 5,
            run: function (c) {
                var hosts = {};
                Array.prototype.forEach.call(c.doc.querySelectorAll('script[src]'), function (s) {
                    try {
                        var u = new URL(s.src, c.href);
                        if (u.host && !sameSite(u.host, c.host)) { hosts[u.host] = true; }
                    } catch (e) { /* ignore */ }
                });
                var list = Object.keys(hosts);
                return list.length > 5
                    ? 'Scripts are loaded from ' + list.length + ' external domains (' + short(list.slice(0, 3).join(', '), 60) + '…).'
                    : null;
            }
        },
        {
            id: 'spam-phrases',
            title: 'No classic spam wording in the text',
            failTitle: 'Classic spam wording in the text',
            category: 'Content',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var text = c.text.toLowerCase();
                var hits = countOccurrences(text, SPAM_PHRASES);
                if (!hits.length) { return null; }
                return {
                    detail: hits.length + ' spam phrase(s) found: "' + hits.slice(0, 4).join('", "') + '".',
                    points: clamp(hits.length * 3, 3, 12)
                };
            }
        },
        {
            id: 'shouty-text',
            title: 'Text is not written in shouting style',
            failTitle: 'Text is written in shouting style',
            category: 'Content',
            needsDom: true,
            weight: 4,
            run: function (c) {
                var text = c.text;
                if (text.length < 200) { return null; }
                var letters = text.replace(/[^A-Za-z]/g, '');
                if (letters.length < 100) { return null; }
                var upper = (text.match(/[A-Z]/g) || []).length / letters.length;
                var bangs = (text.match(/!/g) || []).length;
                if (upper > 0.35 || bangs > 15) {
                    return Math.round(upper * 100) + '% of the letters are upper case and the page uses ' + bangs + ' exclamation marks.';
                }
                return null;
            }
        },
        {
            id: 'obfuscated-js',
            title: 'Inline scripts are not obfuscated',
            failTitle: 'Inline scripts look obfuscated',
            category: 'Scripts',
            needsDom: true,
            weight: 8,
            run: function (c) {
                var code = '';
                Array.prototype.forEach.call(c.doc.querySelectorAll('script:not([src])'), function (s) {
                    code += s.textContent + '\n';
                });
                code = code.slice(0, 120000);
                var hits = countOccurrences(code, OBFUSCATION_TOKENS);
                return hits.length >= 2
                    ? 'Inline scripts use ' + hits.slice(0, 4).join(', ') + ' which are typical of obfuscated code.'
                    : null;
            }
        },
        {
            id: 'meta-refresh',
            title: 'No automatic redirect',
            failTitle: 'Page redirects automatically',
            category: 'Content',
            needsDom: true,
            weight: 6,
            run: function (c) {
                var meta = c.doc.querySelector('meta[http-equiv="refresh"], meta[http-equiv="REFRESH"]');
                return meta
                    ? 'The page redirects automatically (meta refresh: ' + short(meta.getAttribute('content'), 40) + ').'
                    : null;
            }
        },
        {
            id: 'popup-traps',
            title: 'No pop-up / leave-page traps',
            failTitle: 'Pop-up / leave-page traps',
            category: 'Scripts',
            needsDom: true,
            weight: 5,
            run: function (c) {
                var html = c.doc.documentElement.outerHTML.slice(0, 200000);
                var traps = [];
                if (/onbeforeunload/i.test(html)) { traps.push('blocks leaving the page'); }
                if ((html.match(/window\.open\s*\(/gi) || []).length > 1) { traps.push('opens pop-up windows'); }
                if (/oncontextmenu\s*=\s*["']?return false/i.test(html)) { traps.push('disables the right-click menu'); }
                return traps.length ? 'The page ' + traps.join(', ') + '.' : null;
            }
        },
        {
            id: 'hidden-text',
            title: 'No invisible keyword stuffing',
            failTitle: 'Invisible keyword stuffing',
            category: 'Content',
            needsDom: true,
            weight: 6,
            run: function (c) {
                var chars = 0;
                var nodes = c.doc.querySelectorAll('div, span, p, section, ul');
                for (var i = 0; i < nodes.length && i < 600; i++) {
                    var el = nodes[i];
                    var txt = (el.textContent || '').trim();
                    if (txt.length < 60) { continue; }
                    var st = elementStyle(c.doc, el);
                    if (!st) { continue; }
                    var fontSize = parseFloat(st.fontSize || '16');
                    if (st.display === 'none' || st.visibility === 'hidden' || fontSize < 3 ||
                        Number(st.opacity) === 0 || st.color === st.backgroundColor) {
                        chars += txt.length;
                    }
                }
                return chars > 400
                    ? 'About ' + chars + ' characters of text are hidden from the visitor but visible to search engines.'
                    : null;
            }
        },
        {
            id: 'external-links',
            title: 'Links mostly stay on this site',
            failTitle: 'Most links leave this site',
            category: 'Content',
            needsDom: true,
            weight: 5,
            run: function (c) {
                var total = 0, external = 0;
                Array.prototype.forEach.call(c.doc.querySelectorAll('a[href]'), function (a) {
                    var href = a.getAttribute('href');
                    if (!href || href.charAt(0) === '#' || /^(javascript|mailto|tel):/i.test(href)) { return; }
                    try {
                        var u = new URL(href, c.href);
                        total++;
                        if (u.host && !sameSite(u.host, c.host)) { external++; }
                    } catch (e) { /* ignore */ }
                });
                if (total >= 20 && external / total > 0.7) {
                    return Math.round(external / total * 100) + '% of the ' + total + ' links leave this site (link farm pattern).';
                }
                return null;
            }
        },
        {
            id: 'site-identity',
            title: 'Page has a proper identity',
            failTitle: 'Page has no proper identity',
            category: 'Content',
            needsDom: true,
            weight: 3,
            run: function (c) {
                var missing = [];
                if (!c.doc.title || !c.doc.title.trim()) { missing.push('title'); }
                if (!c.doc.querySelector('link[rel*="icon"]')) { missing.push('favicon'); }
                if (!c.doc.querySelector('meta[name="description"]')) { missing.push('description'); }
                return missing.length >= 2
                    ? 'The page has no ' + missing.join(', ') + '.'
                    : null;
            }
        },
        {
            id: 'overlay-ads',
            title: 'No full screen overlay / pop-under',
            failTitle: 'Full screen overlay / pop-under',
            category: 'Content',
            needsDom: true,
            weight: 5,
            run: function (c) {
                var overlays = 0;
                var nodes = c.doc.querySelectorAll('div, section, aside');
                for (var i = 0; i < nodes.length && i < 600; i++) {
                    var st = elementStyle(c.doc, nodes[i]);
                    if (!st) { continue; }
                    var z = parseInt(st.zIndex, 10);
                    if ((st.position === 'fixed' || st.position === 'absolute') && z > 9999) { overlays++; }
                }
                return overlays > 1
                    ? overlays + ' floating overlay layers were found on top of the content.'
                    : null;
            }
        },
        {
            id: 'auto-download',
            title: 'No forced file download',
            failTitle: 'Executable file download offered',
            category: 'Downloads',
            needsDom: true,
            weight: 8,
            run: function (c) {
                var bad = [];
                Array.prototype.forEach.call(c.doc.querySelectorAll('a[href]'), function (a) {
                    var href = (a.getAttribute('href') || '').toLowerCase().split('?')[0];
                    EXECUTABLE_EXT.forEach(function (ext) {
                        if (href.length > ext.length && href.indexOf(ext) === href.length - ext.length) {
                            bad.push(href.split('/').pop());
                        }
                    });
                });
                return bad.length
                    ? 'The page offers executable download(s): ' + short(bad.slice(0, 3).join(', '), 60) + '.'
                    : null;
            }
        },
        {
            id: 'mixed-content',
            title: 'No insecure resources on a secure page',
            failTitle: 'Insecure resources on a secure page',
            category: 'Transport',
            needsDom: true,
            weight: 7,
            run: function (c) {
                if (c.url.protocol !== 'https:') { return null; }
                var insecure = c.doc.querySelectorAll('script[src^="http://"], iframe[src^="http://"], link[href^="http://"]').length;
                return insecure
                    ? insecure + ' resource(s) are loaded over plain HTTP on an HTTPS page (mixed content).'
                    : null;
            }
        },
        {
            id: 'fake-urgency',
            title: 'No artificial time pressure',
            failTitle: 'Artificial time pressure',
            category: 'Content',
            needsDom: true,
            weight: 4,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), URGENCY_PHRASES);
                return hits.length >= 2
                    ? 'The page pushes urgency: "' + hits.slice(0, 3).join('", "') + '".'
                    : null;
            }
        },
        {
            id: 'contact-info',
            title: 'Site provides contact information',
            failTitle: 'No contact information on the page',
            category: 'Content',
            needsDom: true,
            weight: 3,
            run: function (c) {
                var html = (c.doc.body ? c.doc.body.innerHTML : '').slice(0, 200000);
                var hasContact = /mailto:/i.test(html) ||
                                 /(contact|about|imprint|impressum|privacy)/i.test(html);
                if (hasContact) { return null; }
                if (c.text.length < 400) { return null; }   // tiny pages are not judged
                return 'No contact, about or privacy information could be found on the page.';
            }
        }
    ];

    /* -------------------------------------------------------------- rating */

    function ratingFor(score) {
        if (score >= 90) { return {grade: 'A', verdict: 'Safe', level: 'safe'}; }
        if (score >= 75) { return {grade: 'B', verdict: 'Probably safe', level: 'ok'}; }
        if (score >= 60) { return {grade: 'C', verdict: 'Use caution', level: 'caution'}; }
        if (score >= 40) { return {grade: 'D', verdict: 'Suspicious', level: 'risky'}; }
        return {grade: 'F', verdict: 'Likely spam / unsafe', level: 'danger'};
    }

    function severityFor(points) {
        if (points >= 10) { return 'high'; }
        if (points >= 5) { return 'medium'; }
        return 'low';
    }

    /* ------------------------------------------------------------ analyse */

    /**
     * Analyse a page.
     * @param {Object|string} options  URL string, or {url, document}
     * @returns {Object} full report
     */
    function analyze(options) {
        if (typeof options === 'string') { options = {url: options}; }
        options = options || {};

        var href = options.url || (typeof location !== 'undefined' ? location.href : '');
        var doc = options.document || null;
        var url = parseUrl(href);

        if (!url) {
            return {
                url: href,
                score: 0,
                penalty: 100,
                rating: 'F',
                verdict: 'Invalid address',
                level: 'danger',
                checks: [],
                failed: [],
                passed: [],
                skipped: [],
                analysedAt: new Date().toISOString(),
                error: 'The address "' + href + '" could not be parsed.'
            };
        }

        var ctx = {
            href: href,
            url: url,
            host: url.hostname.toLowerCase(),
            domain: registrableDomain(url.hostname),
            doc: doc,
            text: doc ? visibleText(doc) : ''
        };

        var results = [];
        var penalty = 0;

        CHECKS.forEach(function (check) {
            var entry = {
                id: check.id,
                title: check.title,          // replaced by failTitle when the test fails
                category: check.category,
                weight: check.weight,
                status: 'passed',
                points: 0,
                detail: ''
            };

            if (check.needsDom && !doc) {
                entry.status = 'skipped';
                entry.detail = 'Needs the page content (URL only scan).';
                results.push(entry);
                return;
            }

            var outcome;
            try {
                outcome = check.run(ctx);
            } catch (e) {
                entry.status = 'skipped';
                entry.detail = 'Test could not run: ' + e.message;
                results.push(entry);
                return;
            }

            if (outcome) {
                var detail = typeof outcome === 'string' ? outcome : outcome.detail;
                var points = typeof outcome === 'string' ? check.weight : outcome.points;
                points = clamp(points, 1, check.weight);
                entry.status = 'failed';
                entry.title = check.failTitle || check.title;
                entry.points = points;
                entry.detail = detail;
                entry.severity = severityFor(points);
                penalty += points;
            } else {
                entry.detail = 'OK';
            }
            results.push(entry);
        });

        /*
         * Normalising the score.
         * A URL-only scan can only run the 16 address tests, so its penalty
         * must be measured against the weight that was actually available -
         * otherwise every URL would look safe simply because the page content
         * tests were skipped. RISK_SPAN says "a page that collects 40% of the
         * available penalty weight scores zero".
         */
        var available = results.reduce(function (sum, r) {
            return r.status === 'skipped' ? sum : sum + r.weight;
        }, 0);
        var riskRatio = available ? penalty / available : 0;
        var score = clamp(Math.round(100 - (riskRatio / RISK_SPAN) * 100), 0, 100);
        var rating = ratingFor(score);

        var failed = results.filter(function (r) { return r.status === 'failed'; })
                            .sort(function (a, b) { return b.points - a.points; });

        return {
            url: href,
            host: ctx.host,
            domain: ctx.domain,
            score: score,
            penalty: penalty,
            maxPenalty: available,
            riskRatio: Math.round(riskRatio * 1000) / 1000,
            rating: rating.grade,
            verdict: rating.verdict,
            level: rating.level,
            isSpam: score < 60,
            checks: results,
            failed: failed,
            passed: results.filter(function (r) { return r.status === 'passed'; }),
            skipped: results.filter(function (r) { return r.status === 'skipped'; }),
            totalTests: results.length,
            analysedAt: new Date().toISOString()
        };
    }

    return {
        analyze: analyze,
        analyse: analyze,               // British spelling alias
        ratingFor: ratingFor,
        registrableDomain: registrableDomain,
        checks: CHECKS,
        version: '1.0.0'
    };
}));
