/*
 * spam-analyzer.js  --  Demo 4 (Lab 4)
 * ---------------------------------------------------------------------------
 * Heuristic spam / phishing analyser.
 *
 * Loaded by the extension's content script (window.SpamAnalyzer) and by the
 * Node.js unit tests (require('./spam-analyzer')).
 *
 * It performs 49 independent tests. Every test that "hits" adds penalty points;
 * the score is derived from the penalty relative to the tests that could run,
 * and a few near-conclusive tests also cap it (see analyze()).
 *
 * NOTE: this is a client side heuristic scanner written for a lab exercise.
 * It never contacts a remote blocklist, so it can produce false positives and
 * must not be treated as real anti-phishing protection.
 * ---------------------------------------------------------------------------
 */
(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();               // Node.js unit tests
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

    /*
     * Wording is split in two. The strong list is scam vocabulary that an
     * honest page has no reason to use; the weak list is ordinary marketing
     * copy that any real shop writes, so it only counts once several appear
     * together. Without that split a legitimate checkout page saying
     * "order now" and "buy now" would be reported as spam.
     */
    var SPAM_PHRASES_STRONG = [
        'you have won', 'you won', 'congratulations you', 'claim your prize',
        'free money', 'make money fast', 'earn extra cash', 'double your money',
        'miracle cure', 'lose weight fast', 'viagra', 'casino bonus',
        'crypto giveaway', 'wire transfer fee', 'western union', 'nigerian prince',
        'inheritance fund', 'unclaimed funds', 'winner selected', 'this is not a scam',
        'guaranteed income', 'hot singles', 'bulk email', 'weight loss pill',
        'cheap meds', 'no credit check', 'pre-approved loan', '100% free'
    ];

    var SPAM_PHRASES_WEAK = [
        'risk free', 'act now', 'limited time offer', 'click here now', 'order now',
        'buy now', 'lowest price', 'work from home', 'free gift', 'gift card',
        'investment opportunity', 'increase your traffic', 'seo services'
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

    /*
     * Scareware wording, split the same way: real banks legitimately write
     * "security alert" and "unusual sign-in activity", so those only count
     * when several appear together or next to genuine coercion.
     */
    var SCAREWARE_STRONG = [
        'your computer is infected', 'your device is infected', 'virus detected',
        'system is damaged', 'call support now', 'call microsoft', 'call apple support',
        'your pc is at risk', 'malware detected', 'do not close this window',
        'your files have been encrypted'
    ];

    var SCAREWARE_WEAK = [
        'immediate action required', 'security alert', 'your account has been locked',
        'unusual sign-in activity', 'suspicious activity detected', 'verify your identity now'
    ];

    // Well known brand domains, used for typo-squatting distance checks.
    var BRAND_DOMAINS = [
        'paypal.com', 'apple.com', 'icloud.com', 'microsoft.com', 'outlook.com',
        'google.com', 'gmail.com', 'facebook.com', 'instagram.com', 'netflix.com',
        'amazon.com', 'ebay.com', 'linkedin.com', 'dropbox.com', 'steampowered.com',
        'binance.com', 'coinbase.com', 'whatsapp.com', 'roblox.com', 'discord.com'
    ];

    // Query parameters that usually carry a second URL (open redirect).
    var REDIRECT_PARAMS = ['url', 'redirect', 'redirect_url', 'redir', 'next', 'goto',
                           'target', 'dest', 'destination', 'continue', 'return', 'returnurl', 'r', 'u'];

    // Public suffix labels that must not show up inside a sub-domain.
    var TLD_IN_SUBDOMAIN = ['com', 'net', 'org', 'gov', 'edu', 'co.uk', 'com.au', 'io', 'info'];

    // Names of fields that collect payment or identity data.
    var PAYMENT_FIELD_WORDS = ['card', 'cardnumber', 'card_number', 'ccnum', 'cc-number',
                               'creditcard', 'cvv', 'cvc', 'securitycode', 'card-security',
                               'expiry', 'exp-date', 'ssn', 'social-security', 'sortcode',
                               'iban', 'accountnumber', 'routing', 'pin'];

    // Permission prompts that spam pages fire on load.
    var PERMISSION_CALLS = ['Notification.requestPermission', 'requestPermission(',
                            'geolocation.getCurrentPosition', 'geolocation.watchPosition',
                            'getUserMedia(', 'PushManager'];

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

    /** Levenshtein distance, used to spot typo-squatted brand domains. */
    function editDistance(a, b) {
        if (a === b) { return 0; }
        if (Math.abs(a.length - b.length) > 3) { return 99; }   // cheap early exit
        var previous = [];
        var i, j;
        for (j = 0; j <= b.length; j++) { previous[j] = j; }
        for (i = 1; i <= a.length; i++) {
            var current = [i];
            for (j = 1; j <= b.length; j++) {
                current[j] = Math.min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1)
                );
            }
            previous = current;
        }
        return previous[b.length];
    }

    /*
     * new URL() normalises an international host name to its punycode form, so
     * "p<cyrillic a>ypal.com" arrives here as "xn--pypal-4ve.com". Decoding it
     * back (RFC 3492) is what makes the homograph test possible, and it also
     * keeps genuine international domains from being punished: they decode to a
     * single alphabet, a spoof decodes to a mixture.
     */
    function punycodeAdapt(delta, numPoints, firstTime) {
        delta = firstTime ? Math.floor(delta / 700) : delta >> 1;
        delta += Math.floor(delta / numPoints);
        var k = 0;
        while (delta > 455) {
            delta = Math.floor(delta / 35);
            k += 36;
        }
        return k + Math.floor((36 * delta) / (delta + 38));
    }

    function decodeLabel(label) {
        if (label.slice(0, 4).toLowerCase() !== 'xn--') { return label; }
        var input = label.slice(4);
        var base = 36, tmin = 1, tmax = 26;
        var n = 128, bias = 72, i = 0;
        var output = [];
        var delimiter = input.lastIndexOf('-');
        var index = 0;
        var j;

        if (delimiter > 0) {
            for (j = 0; j < delimiter; j++) { output.push(input.charCodeAt(j)); }
            index = delimiter + 1;
        }

        while (index < input.length) {
            var oldi = i;
            var weight = 1;
            var k = base;
            for (;;) {
                if (index >= input.length) { return label; }        // malformed
                var code = input.charCodeAt(index++);
                var digit;
                if (code >= 0x30 && code <= 0x39) { digit = code - 0x30 + 26; }
                else if (code >= 0x61 && code <= 0x7A) { digit = code - 0x61; }
                else if (code >= 0x41 && code <= 0x5A) { digit = code - 0x41; }
                else { return label; }
                i += digit * weight;
                var t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
                if (digit < t) { break; }
                weight *= (base - t);
                k += base;
            }
            var outLength = output.length + 1;
            bias = punycodeAdapt(i - oldi, outLength, oldi === 0);
            n += Math.floor(i / outLength);
            i %= outLength;
            if (n > 0x10FFFF) { return label; }
            output.splice(i, 0, n);
            i++;
        }

        try {
            return String.fromCodePoint.apply(String, output);
        } catch (e) {
            return label;
        }
    }

    function decodeHost(host) {
        if (String(host).indexOf('xn--') === -1) { return host; }
        try {
            return host.split('.').map(decodeLabel).join('.');
        } catch (e) {
            return host;
        }
    }

    /** Which Unicode scripts a single host label uses (homograph attacks). */
    function scriptsUsed(label) {
        var scripts = {};
        for (var i = 0; i < label.length; i++) {
            var code = label.charCodeAt(i);
            if ((code >= 0x41 && code <= 0x7A) ||
                (code >= 0xC0 && code <= 0x24F)) { scripts.latin = true; }   // incl. ä, ü, ñ
            else if (code >= 0x0400 && code <= 0x04FF) { scripts.cyrillic = true; }
            else if (code >= 0x0370 && code <= 0x03FF) { scripts.greek = true; }
            else if (code >= 0x0590 && code <= 0x05FF) { scripts.hebrew = true; }
            else if (code >= 0x0600 && code <= 0x06FF) { scripts.arabic = true; }
            else if (code > 0x2000) { scripts.other = true; }
        }
        return Object.keys(scripts);
    }

    /*
     * Characters from other alphabets that are drawn like Latin letters.
     * Mapping them back is what turns the Cyrillic "\u0430\u0440\u0440\u04cf\u0435" into
     * "apple", which is the only way to see that an all-Cyrillic domain is
     * impersonating a brand.
     */
    var CONFUSABLES = {
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
        '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
        '\u0501': 'd', '\u04cf': 'l', '\u043a': 'k', '\u043c': 'm', '\u043d': 'h',
        '\u0442': 'r', '\u0432': 'b', '\u0433': 'r', '\u04bb': 'h', '\u051b': 'q',
        '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03b5': 'e', '\u03b9': 'i',
        '\u03ba': 'k', '\u03bd': 'v', '\u03c4': 't', '\u03c5': 'u', '\u03c7': 'x',
        '\u1d00': 'a', '\u0261': 'g', '\u04ab': 'c'
    };

    /** Rewrite a name using Latin look-alikes, so spoofs can be compared. */
    function latinSkeleton(text) {
        var out = '';
        for (var i = 0; i < text.length; i++) {
            out += CONFUSABLES[text[i]] || text[i];
        }
        return out;
    }

    /** Shannon entropy per character - random looking domains score high. */
    function entropy(text) {
        var counts = {};
        var i;
        for (i = 0; i < text.length; i++) { counts[text[i]] = (counts[text[i]] || 0) + 1; }
        var total = text.length;
        var sum = 0;
        Object.keys(counts).forEach(function (ch) {
            var p = counts[ch] / total;
            sum -= p * (Math.log(p) / Math.LN2);
        });
        return sum;
    }

    /*
     * Longest run of consonants - "xkqzrt" style generated domains. Words are
     * split on hyphens and digits first: without that, "plain-http-site"
     * collapses to "plainhttpsite" and invents a six-consonant run that the
     * name does not actually contain.
     */
    function longestConsonantRun(text) {
        var longest = 0;
        text.toLowerCase().split(/[^a-z]+/).forEach(function (word) {
            word.split(/[aeiouy]+/).forEach(function (run) {
                longest = Math.max(longest, run.length);
            });
        });
        return longest;
    }

    function short(text, max) {
        text = String(text).replace(/\s+/g, ' ').trim();
        return text.length > max ? text.slice(0, max - 1) + '…' : text;
    }

    /** Visible text of the page, capped so huge pages stay fast. */
    function visibleText(doc) {
        var body = doc && doc.body;
        if (!body) { return ''; }
        try {
            return (body.innerText || body.textContent || '').slice(0, 200000);
        } catch (e) {
            return '';
        }
    }

    /** True when two hosts belong to the same site. Ports are ignored: one side
     *  often comes from URL.host ("localhost:8484") and the other from
     *  URL.hostname ("localhost"), and a port never changes the site. */
    function sameSite(hostA, hostB) {
        var strip = function (host) { return String(host).replace(/:\d+$/, ''); };
        return registrableDomain(strip(hostA)) === registrableDomain(strip(hostB));
    }

    /** Addresses the browser itself treats as trusted local development. */
    function isLocalAddress(host) {
        var name = String(host).replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
        return name === 'localhost' || name === '127.0.0.1' || name === '::1' ||
               /\.localhost$/.test(name);
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
                if (c.url.protocol === 'https:' || c.url.protocol === 'file:') { return null; }
                /* Browsers treat http://localhost as a secure context, so a
                   local development page is not penalised here. */
                if (isLocalAddress(c.host)) { return null; }
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
            title: 'Domain is plain ASCII',
            failTitle: 'Domain uses international characters',
            category: 'URL',
            weight: 6,
            run: function (c) {
                if (c.host.indexOf('xn--') === -1) { return null; }
                return 'The domain is stored as "' + c.host + '" and displays as "' +
                       c.decodedHost + '". Check that it reads the way you expect.';
            }
        },
        {
            id: 'at-symbol',
            cap: 40,
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
                var notInDomain = function (brand) { return c.domain.indexOf(brand) === -1; };
                var host = subdomainLabels(c.host).join('.').toLowerCase();
                var path = c.url.pathname.toLowerCase();

                // A brand in the sub-domain is the classic phishing shape.
                var hostHits = countOccurrences(host, BRANDS).filter(notInDomain);
                if (hostHits.length) {
                    return {
                        detail: 'The sub-domain claims "' + hostHits.join('", "') +
                                '" but the real domain is ' + c.domain + '.',
                        points: 12,
                        cap: 45          // conclusive on its own
                    };
                }

                /* A brand in the path is only meaningful next to a credential
                   word - otherwise ordinary pages such as
                   /blog/how-to-use-google-analytics would be flagged. */
                var pathHits = countOccurrences(path, BRANDS).filter(notInDomain);
                if (pathHits.length && countOccurrences(path, SENSITIVE_WORDS).length) {
                    return {
                        detail: 'The path mentions "' + pathHits[0] + '" next to sign-in wording, but the domain is ' + c.domain + '.',
                        points: 7
                    };
                }
                return null;
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
                // Measured on the decoded name: "xn--mnchen-3ya.de" is not hyphenated.
                var hyphens = (c.decodedDomain.match(/-/g) || []).length;
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
                var digits = (c.decodedDomain.match(/\d/g) || []).length;
                return (digits >= 5 || digits / Math.max(1, c.decodedDomain.length) > 0.3)
                    ? 'The domain "' + c.decodedDomain + '" contains ' + digits + ' digits.'
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
                if (!c.url.port || isLocalAddress(c.host)) { return null; }
                var ok = ['80', '443', '8080', '8000', '8443', '3000', '5000'];
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
            cap: 50,
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

        {
            id: 'unsafe-scheme',
            cap: 45,
            failTitle: 'Page is not loaded from a normal web address',
            title: 'Loaded from a normal web address',
            category: 'Transport',
            weight: 10,
            run: function (c) {
                var safe = ['http:', 'https:', 'file:'];
                return safe.indexOf(c.url.protocol) === -1
                    ? 'The page uses the "' + c.url.protocol + '" scheme instead of http(s).'
                    : null;
            }
        },
        {
            id: 'mixed-scripts',
            cap: 30,
            failTitle: 'Domain is a look-alike of another name',
            title: 'Domain is not a look-alike',
            category: 'URL',
            weight: 12,
            run: function (c) {
                var labels = c.decodedHost.split('.');

                /* Scripts are compared inside each label. Comparing the whole
                   host would flag every legitimate international domain, since
                   the ending (.jp, .de) is always Latin. */
                for (var i = 0; i < labels.length; i++) {
                    var scripts = scriptsUsed(labels[i]);
                    if (scripts.length > 1) {
                        return 'The address displays as "' + c.decodedHost + '" and the part "' +
                               labels[i] + '" mixes ' + scripts.join(' and ') +
                               ' characters - a look-alike domain.';
                    }
                }

                /* A label written entirely in another alphabet is fine on its
                   own (a Russian or Greek site), but not when the look-alike
                   letters spell out a well known brand. */
                var skeleton = latinSkeleton(c.decodedHost);
                if (skeleton === c.decodedHost) { return null; }
                var skeletonDomain = registrableDomain(skeleton);
                var base = skeletonDomain.split('.')[0];
                var impersonates = BRANDS.indexOf(base) !== -1 ||
                    BRAND_DOMAINS.some(function (brand) { return editDistance(skeletonDomain, brand) <= 1; });
                return impersonates
                    ? 'The domain is written in another alphabet but reads as "' + skeletonDomain +
                      '" - it is imitating that brand.'
                    : null;
            }
        },
        {
            id: 'typosquat-brand',
            cap: 30,
            failTitle: 'Domain is a near-miss of a well known brand',
            title: 'Domain is not a misspelt brand',
            category: 'URL',
            weight: 14,
            run: function (c) {
                if (BRAND_DOMAINS.indexOf(c.domain) !== -1) { return null; }   // the real thing
                for (var i = 0; i < BRAND_DOMAINS.length; i++) {
                    var distance = editDistance(c.domain, BRAND_DOMAINS[i]);
                    if (distance > 0 && distance <= 2) {
                        return '"' + c.domain + '" is only ' + distance +
                               ' character(s) away from "' + BRAND_DOMAINS[i] + '".';
                    }
                }
                return null;
            }
        },
        {
            id: 'tld-in-subdomain',
            cap: 45,
            failTitle: 'A domain ending is buried in the sub-domain',
            title: 'No fake domain ending in the sub-domain',
            category: 'URL',
            weight: 10,
            run: function (c) {
                var labels = subdomainLabels(c.host);
                var joined = labels.join('.');
                var hit = TLD_IN_SUBDOMAIN.filter(function (tld) {
                    return labels.indexOf(tld) !== -1 || joined.indexOf('.' + tld + '.') !== -1;
                });
                return hit.length
                    ? 'The address reads like "' + joined + '" but the real domain is "' + c.domain + '".'
                    : null;
            }
        },
        {
            id: 'redirect-param',
            failTitle: 'Address carries another URL as a parameter',
            title: 'No redirect parameter in the address',
            category: 'URL',
            weight: 7,
            run: function (c) {
                var found = null;
                c.url.search.replace(/^\?/, '').split('&').forEach(function (pair) {
                    var bits = pair.split('=');
                    var key = decodeURIComponent(bits[0] || '').toLowerCase();
                    var value = decodeURIComponent(bits.slice(1).join('=') || '');
                    if (REDIRECT_PARAMS.indexOf(key) !== -1 && /^(https?:)?\/\//i.test(value)) {
                        found = key + '=' + short(value, 40);
                    }
                });
                return found
                    ? 'The parameter "' + found + '" sends the browser to another site (open redirect).'
                    : null;
            }
        },
        {
            id: 'random-domain',
            failTitle: 'Domain looks machine generated',
            title: 'Domain looks human readable',
            category: 'URL',
            weight: 6,
            run: function (c) {
                if (isIpHost(c.host)) { return null; }
                var label = c.decodedDomain.split('.')[0];
                if (label.length < 8) { return null; }
                var bits = entropy(label);
                var run = longestConsonantRun(label);
                if (bits > 3.6 || run >= 5) {
                    return '"' + label + '" has the shape of a generated domain (entropy ' +
                           bits.toFixed(1) + ', ' + run + ' consonants in a row).';
                }
                return null;
            }
        },
        {
            id: 'hostname-length',
            failTitle: 'Host name is abnormally long',
            title: 'Host name has a sensible length',
            category: 'URL',
            weight: 4,
            run: function (c) {
                return c.host.length > 40
                    ? 'The host name is ' + c.host.length + ' characters long.'
                    : null;
            }
        },

        /* -------------------------------- page content tests */
        {
            id: 'insecure-password-form',
            cap: 40,
            title: 'Passwords are not requested over an insecure page',
            failTitle: 'Password requested over an insecure page',
            category: 'Forms',
            needsDom: true,
            weight: 15,
            run: function (c) {
                var pw = c.doc.querySelectorAll('input[type="password"]').length;
                if (!pw) { return null; }
                if (c.url.protocol === 'https:' || c.url.protocol === 'file:') { return null; }
                if (isLocalAddress(c.host)) { return null; }
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
                var strong = countOccurrences(text, SPAM_PHRASES_STRONG);
                var weak = countOccurrences(text, SPAM_PHRASES_WEAK);

                if (strong.length) {
                    return {
                        detail: 'Scam wording found: "' + strong.slice(0, 4).join('", "') + '"' +
                                (weak.length ? ', plus ' + weak.length + ' hard-sell phrase(s).' : '.'),
                        points: clamp(strong.length * 4 + weak.length, 4, 12)
                    };
                }

                // Marketing copy alone only counts when the page is full of it.
                if (weak.length >= 3) {
                    return {
                        detail: weak.length + ' hard-sell phrases: "' + weak.slice(0, 4).join('", "') +
                                '". Common on real shops too.',
                        points: clamp(weak.length, 3, 4)
                    };
                }
                return null;
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
            id: 'payment-fields',
            failTitle: 'Page asks for card or identity details',
            title: 'No card or identity details requested',
            category: 'Forms',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var found = {};
                Array.prototype.forEach.call(c.doc.querySelectorAll('input, select'), function (field) {
                    var hay = ((field.name || '') + ' ' + (field.id || '') + ' ' +
                               (field.getAttribute('autocomplete') || '') + ' ' +
                               (field.placeholder || '')).toLowerCase().replace(/\s+/g, '');
                    PAYMENT_FIELD_WORDS.forEach(function (word) {
                        if (hay.indexOf(word.replace(/[-_]/g, '')) !== -1) { found[word] = true; }
                    });
                });
                var list = Object.keys(found);
                if (!list.length) { return null; }
                var secure = c.url.protocol === 'https:' || isLocalAddress(c.host);
                return {
                    detail: 'The page collects ' + list.slice(0, 4).join(', ') +
                            (secure ? '. Only enter these on a site you trust.'
                                    : ' over an unencrypted connection.'),
                    points: secure ? 4 : 12
                };
            }
        },
        {
            id: 'favicon-hotlink',
            failTitle: 'Site icon is borrowed from another domain',
            title: 'Site icon is served by this site',
            category: 'Content',
            needsDom: true,
            weight: 7,
            run: function (c) {
                var icon = c.doc.querySelector('link[rel*="icon"][href]');
                if (!icon) { return null; }
                var href = icon.getAttribute('href');
                if (!href || /^data:/i.test(href)) { return null; }
                try {
                    var iconUrl = new URL(href, c.href);
                    if (iconUrl.host && !sameSite(iconUrl.host, c.host)) {
                        return 'The tab icon is loaded from ' + iconUrl.host +
                               ', which is how a copied page keeps the original branding.';
                    }
                } catch (e) { /* ignore */ }
                return null;
            }
        },
        {
            id: 'title-brand-mismatch',
            cap: 40,
            failTitle: 'Page claims a brand that does not own the domain',
            title: 'Page title matches the domain',
            category: 'Content',
            needsDom: true,
            weight: 12,
            run: function (c) {
                /* Only a sign-in page can impersonate a brand; without a password
                   field this would flag any article that mentions a company. */
                if (!c.doc.querySelector('input[type="password"]')) { return null; }
                var heading = c.doc.querySelector('h1');
                var claim = ((c.doc.title || '') + ' ' + (heading ? heading.textContent : '')).toLowerCase();
                var hits = countOccurrences(claim, BRANDS).filter(function (brand) {
                    return c.domain.indexOf(brand) === -1;
                });
                return hits.length
                    ? 'The page presents itself as "' + hits[0] + '" but is served from ' + c.domain + '.'
                    : null;
            }
        },
        {
            id: 'deceptive-links',
            failTitle: 'Link text does not match where the link goes',
            title: 'Link text matches the link target',
            category: 'Content',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var bad = [];
                Array.prototype.forEach.call(c.doc.querySelectorAll('a[href]'), function (a) {
                    if (bad.length >= 3) { return; }
                    var text = (a.textContent || '').trim().toLowerCase();
                    // Only links whose text is itself a domain or URL can lie about the target.
                    var match = text.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/?#].*)?$/);
                    if (!match) { return; }
                    try {
                        var target = new URL(a.getAttribute('href'), c.href);
                        if (target.host && !sameSite(target.host, match[1])) {
                            bad.push('"' + short(text, 28) + '" goes to ' + target.host);
                        }
                    } catch (e) { /* ignore */ }
                });
                return bad.length >= 2 ? bad.join('; ') + '.' : null;
            }
        },
        {
            id: 'full-page-iframe',
            failTitle: 'Whole page is another site in a frame',
            title: 'Page is not a frame around another site',
            category: 'Content',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var view = c.doc.defaultView;
                if (!view || !view.innerWidth) { return null; }
                var area = view.innerWidth * view.innerHeight;
                var found = null;
                Array.prototype.forEach.call(c.doc.querySelectorAll('iframe[src]'), function (frame) {
                    if (found || !frame.getBoundingClientRect) { return; }
                    var box = frame.getBoundingClientRect();
                    if (area && (box.width * box.height) / area > 0.7) {
                        try {
                            var src = new URL(frame.getAttribute('src'), c.href);
                            if (src.host && !sameSite(src.host, c.host)) { found = src.host; }
                        } catch (e) { /* ignore */ }
                    }
                });
                return found
                    ? 'Almost the whole page is a frame showing ' + found + ' (cloned site pattern).'
                    : null;
            }
        },
        {
            id: 'scareware',
            failTitle: 'Page uses scare tactics',
            title: 'No scareware or fake alert wording',
            category: 'Content',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var text = c.text.toLowerCase();
                var strong = countOccurrences(text, SCAREWARE_STRONG);
                var weak = countOccurrences(text, SCAREWARE_WEAK);

                if (strong.length) {
                    return {
                        detail: 'Fake alert wording: "' + strong.slice(0, 3).join('", "') + '".',
                        points: clamp(strong.length * 6 + weak.length, 6, 12)
                    };
                }
                // Three alarm phrases and no coercion is still worth a nudge.
                if (weak.length >= 3) {
                    return {
                        detail: 'The page repeats alarm wording: "' + weak.slice(0, 3).join('", "') + '".',
                        points: 5
                    };
                }
                return null;
            }
        },
        {
            id: 'crypto-wallet',
            failTitle: 'Page shows a crypto wallet address',
            title: 'No crypto wallet address on the page',
            category: 'Content',
            needsDom: true,
            weight: 9,
            run: function (c) {
                var text = c.text;
                var bitcoin = text.match(/\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/);
                var ether = text.match(/\b0x[a-fA-F0-9]{40}\b/);
                var hit = bitcoin || ether;
                return hit
                    ? 'A wallet address (' + short(hit[0], 20) + ') is shown - typical of giveaway and ransom scams.'
                    : null;
            }
        },
        {
            id: 'permission-abuse',
            failTitle: 'Page grabs browser permissions on load',
            title: 'No permission prompts on load',
            category: 'Scripts',
            needsDom: true,
            weight: 6,
            run: function (c) {
                var code = '';
                Array.prototype.forEach.call(c.doc.querySelectorAll('script:not([src])'), function (tag) {
                    code += tag.textContent + '\n';
                });
                var hits = countOccurrences(code.slice(0, 120000), PERMISSION_CALLS);
                return hits.length
                    ? 'Inline scripts request browser permissions (' + hits.slice(0, 3).join(', ') + ').'
                    : null;
            }
        },
        {
            id: 'ad-density',
            failTitle: 'Page is dominated by advertising frames',
            title: 'Reasonable amount of advertising',
            category: 'Content',
            needsDom: true,
            weight: 5,
            run: function (c) {
                var adPattern = /(^|[-_ ])(ads?|adsense|adserver|banner|popunder|sponsor|promoted|taboola|outbrain)([-_ ]|$)/i;
                var ads = 0;
                Array.prototype.forEach.call(c.doc.querySelectorAll('iframe, ins, div[id], div[class]'), function (node) {
                    if (ads > 40) { return; }
                    var id = node.getAttribute('id') || '';
                    var cls = node.getAttribute('class') || '';
                    var src = node.getAttribute('src') || '';
                    if (adPattern.test(id) || adPattern.test(cls) || /doubleclick|googlesyndication|adservice/i.test(src)) {
                        ads++;
                    }
                });
                return ads >= 8
                    ? ads + ' advertising containers were found on the page.'
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
            decodedHost: decodeHost(url.hostname.toLowerCase()),
            decodedDomain: registrableDomain(decodeHost(url.hostname.toLowerCase())),
            doc: doc,
            text: doc ? visibleText(doc) : ''
        };

        var results = [];
        var penalty = 0;
        var scoreCap = 100;
        var cappedBy = [];

        /* Page tests walk the DOM, so a huge or hostile page could make the
           scan feel like a freeze. Once the budget is spent the remaining page
           tests are skipped rather than run. */
        var budgetMs = typeof options.budgetMs === 'number' ? options.budgetMs : 2500;
        var deadline = Date.now() + budgetMs;

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

            if (check.needsDom && Date.now() > deadline) {
                entry.status = 'skipped';
                entry.detail = 'Skipped: the scan reached its ' + budgetMs + 'ms time budget.';
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
                // A test may cap the score only for its most serious outcome.
                var cap = (typeof outcome === 'object' && outcome.cap !== undefined)
                    ? outcome.cap : check.cap;
                entry.status = 'failed';
                entry.title = check.failTitle || check.title;
                entry.points = points;
                entry.detail = detail;
                entry.severity = severityFor(points);
                penalty += points;
                if (cap !== undefined) {
                    entry.cap = cap;
                    cappedBy.push(check.id);
                    if (cap < scoreCap) { scoreCap = cap; }
                }
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

        /*
         * Some findings are close to conclusive on their own - a domain one
         * character away from paypal.com, a mixed-alphabet host, a password
         * box on an unencrypted page. Averaging them against 48 tests that
         * passed would hide them, so those tests also cap the final score.
         */
        var uncapped = score;
        score = Math.min(score, scoreCap);
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
            scoreCap: scoreCap,
            cappedBy: score < uncapped ? cappedBy : [],
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
        decodeHost: decodeHost,
        checks: CHECKS,
        version: '1.0.0'
    };
}));
