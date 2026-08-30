/*
 * threat-intel.js  --  VeriSite reputation / known-threat layer
 * ---------------------------------------------------------------------------
 * The heuristics in spam-analyzer.js judge a page by how it is built. Some
 * pages cannot be judged that way at all: an anti-phishing feature test page
 * is ordinary, well written HTML on a reputable domain, and every heuristic
 * passes it. A security product recognises those pages because it knows the
 * address, not because it can see anything wrong with the markup.
 *
 * This file is that missing layer. It holds:
 *
 *   - the published anti-malware feature test pages (AMTSO, Google Safe
 *     Browsing, Mozilla, WICAR, EICAR) that a working filter is expected to
 *     block, so we block them too;
 *   - fingerprints for the parts of a phishing kit that are the same whoever
 *     deploys it - the exfiltration endpoint, the give-away path names;
 *   - the hosting classes (free sub-domain hosts, dynamic DNS) that a
 *     credential page has no honest reason to sit on;
 *   - an empty list an administrator or the user can fill with their own
 *     blocked addresses (see addEntries / loadUserList).
 *
 * Everything here is bundled with the extension and evaluated locally: no
 * address is ever sent anywhere. That means the list is only as fresh as the
 * release, which is why it decides nothing on its own - it is one input to
 * the score alongside the heuristics.
 * ---------------------------------------------------------------------------
 */
(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.VeriSiteThreatIntel = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var FEED_VERSION = '2026.08.30';

    /* --------------------------------------------------------------- utils */

    function hostOf(url) {
        return String(url.hostname || '').toLowerCase().replace(/^www\./, '');
    }

    function registrable(host) {
        var parts = String(host).toLowerCase().split('.');
        var second = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'mil', 'sch'];
        if (parts.length <= 2) { return parts.join('.'); }
        if (second.indexOf(parts[parts.length - 2]) !== -1 && parts[parts.length - 1].length <= 3) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    }

    function endsWithHost(host, suffix) {
        return host === suffix || host.slice(-(suffix.length + 1)) === '.' + suffix;
    }

    /* ------------------------------------------------ published test pages */

    /*
     * AMTSO (the Anti-Malware Testing Standards Organization) publishes a set
     * of "feature settings check" pages. Each one is harmless in itself; the
     * point is that a product with the matching feature switched on must stop
     * you reaching it. Reading the phishing one means the anti-phishing filter
     * did nothing, which is exactly the report the page prints. The slugs have
     * changed over the years, so the path is matched by shape rather than by a
     * fixed list of addresses.
     */
    var AMTSO_PATH = /(feature[-_]?settings[-_]?check|security[-_]?features[-_]?check|^\/check[-_](desktop|mobile|android|ios)[-_]|phishing[-_]page|malware[-_]page|pua[-_]page|potentially[-_]unwanted|drive[-_]?by[-_]download|cloud[-_](lookup|protection)|compressed[-_]malware|check[-_]desktop[-_]download)/i;

    function amtsoKind(path) {
        if (/phish/i.test(path)) {
            return {kind: 'phishing', label: 'AMTSO anti-phishing feature check'};
        }
        if (/pua|potentially[-_]unwanted/i.test(path)) {
            return {kind: 'pua', label: 'AMTSO potentially-unwanted-application feature check'};
        }
        if (/drive[-_]?by/i.test(path)) {
            return {kind: 'malware', label: 'AMTSO drive-by download feature check'};
        }
        if (/cloud/i.test(path)) {
            return {kind: 'malware', label: 'AMTSO cloud-lookup feature check'};
        }
        if (/malware|compressed|download/i.test(path)) {
            return {kind: 'malware', label: 'AMTSO malware download feature check'};
        }
        return {kind: 'test', label: 'AMTSO security feature check'};
    }

    /*
     * The other industry test resources. Each entry says which host it lives
     * on, which paths count, and what a product is supposed to do about it.
     */
    var TEST_RESOURCES = [
        {
            host: 'testsafebrowsing.appspot.com',
            path: /./,
            kind: 'phishing',
            label: 'Google Safe Browsing test page',
            detail: 'Google publishes this address so that a browser\'s Safe Browsing filter can ' +
                    'be verified. Reaching it means nothing blocked it.'
        },
        {
            host: 'itisatrap.org',
            path: /its-a-trap|phishing/i,
            kind: 'phishing',
            label: 'Mozilla anti-phishing test page',
            detail: 'Mozilla\'s published phishing test address, used to verify that a browser\'s ' +
                    'deceptive-site protection is switched on.'
        },
        {
            host: 'itisatrap.org',
            path: /its-an-attack|unwanted|harmful|blocked/i,
            kind: 'malware',
            label: 'Mozilla malware / unwanted-software test page',
            detail: 'Mozilla\'s published attack-site test address. A protected browser stops here.'
        },
        {
            host: 'wicar.org',
            path: /./,
            kind: 'malware',
            label: 'WICAR drive-by download test',
            detail: 'WICAR hosts live browser-exploit test cases. Any security product with ' +
                    'exploit protection is expected to intervene.'
        },
        {
            host: 'eicar.org',
            path: /eicar|download/i,
            kind: 'malware',
            label: 'EICAR anti-malware test file',
            detail: 'The EICAR test string is the industry-standard harmless stand-in for a virus. ' +
                    'An on-access scanner should already have removed it.'
        },
        {
            host: 'eicar.com',
            path: /./,
            kind: 'malware',
            label: 'EICAR anti-malware test file',
            detail: 'The EICAR test string is the industry-standard harmless stand-in for a virus.'
        }
    ];

    /*
     * The EICAR signature, split so that the extension's own source file does
     * not trip a desktop scanner while it sits on disk.
     */
    var EICAR_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR' +
                          '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    /*
     * Wording that only appears on a page whose job is to be blocked. It
     * catches the mirrors and the localised copies that the address rules
     * above cannot know about.
     */
    var TEST_PAGE_SIGNATURES = [
        {
            phrases: ['feature settings check'],
            kind: 'test',
            label: 'Anti-malware feature settings check page'
        },
        {
            phrases: ['your anti-malware solution is not', 'anti-phishing feature is'],
            kind: 'phishing',
            label: 'Anti-phishing feature check page'
        },
        {
            phrases: ['detects phishing pages', 'if you can read this page'],
            kind: 'phishing',
            label: 'Anti-phishing feature check page'
        },
        {
            phrases: ['this is the amtso', 'amtso security features check'],
            kind: 'test',
            label: 'AMTSO security features check page'
        },
        {
            phrases: [EICAR_SIGNATURE.toLowerCase()],
            kind: 'malware',
            label: 'EICAR anti-malware test string'
        }
    ];

    /* ------------------------------------------------- phishing kit shapes */

    /*
     * Where a kit sends what you type. These endpoints need no server of the
     * attacker's own, which is why they turn up in kit after kit; no ordinary
     * login page posts a password to a chat bot.
     */
    var EXFIL_ENDPOINTS = [
        {name: 'Telegram bot API', pattern: /api\.telegram\.org\s*\/\s*bot|sendmessage\?chat_id|chat_id=\s*['"]?-?\d{6,}/i, severity: 'high'},
        {name: 'Discord webhook', pattern: /discord(?:app)?\.com\/api\/webhooks\//i, severity: 'high'},
        {name: 'Slack webhook', pattern: /hooks\.slack\.com\/services\//i, severity: 'medium'},
        {name: 'webhook.site collector', pattern: /webhook\.site\/[0-9a-f-]{8,}/i, severity: 'high'},
        {name: 'requestbin / pipedream collector', pattern: /(requestbin\.\w+|pipedream\.net|beeceptor\.com)/i, severity: 'medium'},
        {name: 'anonymous form relay', pattern: /(formspree\.io|getform\.io|formsubmit\.co|form2channel|staticforms\.xyz|herotofu\.com)/i, severity: 'medium'},
        {name: 'paste site upload', pattern: /(pastebin\.com\/api|paste\.ee\/api|hastebin\.com\/documents)/i, severity: 'medium'},
        {name: 'Google Apps Script relay', pattern: /script\.google\.com\/macros\/s\//i, severity: 'low'},
        {name: 'e-mail relay (mailto exfiltration)', pattern: /action\s*=\s*["']\s*mailto:/i, severity: 'high'}
    ];

    /*
     * Path shapes that come from off-the-shelf kits and from the compromised
     * sites they are dropped onto. A genuine bank does not keep its sign-in
     * page in /wp-content/uploads/.
     */
    var KIT_PATHS = [
        {name: 'PayPal "webscr" clone', pattern: /\/webscr|cmd=_?(login|account|home|update)/i},
        {name: 'kit dropped into a hacked CMS', pattern: /\/wp-(content|includes|admin)\/[^?]*\/(login|signin|verify|secure|account|bank|paypal|office|update)/i},
        {name: 'webmail credential page', pattern: /\/(owa|exchange|webmail|roundcube|cpanel)\/(auth\/)?(logon|login|signin)/i},
        {name: 'copied sign-in flow', pattern: /\/(login|signin|verify|secure|account|update|confirm|password|billing|auth)[^?]*\/(verify|secure|account|update|confirm|billing|password|login|signin)/i},
        {name: 'victim address pre-filled in the link', pattern: /[?&](email|mail|usr|user|login|id)=[^&]*(%40|@)/i},
        {name: 'base64 payload in the address', pattern: /[?&][a-z]{1,4}=(?=[^&]*[A-Z])(?=[^&]*[a-z])(?=[^&]*\d)[A-Za-z0-9+/]{40,}={0,2}(&|$)/},
        {name: 'single-file kit script', pattern: /\/(next|post|send|submit|result|done|blu|log)\.php$/i},
        {name: 'brand folder on an unrelated site', pattern: /\/(paypal|apple|icloud|microsoft|office365|netflix|amazon|dhl|coinbase|metamask)[-_/](login|signin|verify|secure|account|update|support)/i}
    ];

    /* ------------------------------------------------------ hosting classes */

    /*
     * Platforms that hand out a free sub-domain in seconds. They host a great
     * deal of legitimate work, so this is never a verdict on its own - it only
     * matters when the page is also asking for a password or wearing someone
     * else's brand.
     */
    var FREE_HOSTS = [
        'pages.dev', 'workers.dev', 'r2.dev', 'web.app', 'firebaseapp.com',
        'netlify.app', 'vercel.app', 'glitch.me', 'repl.co', 'replit.app',
        'github.io', 'gitlab.io', 'surge.sh', 'onrender.com', 'herokuapp.com',
        '000webhostapp.com', 'weeblysite.com', 'wixsite.com', 'blogspot.com',
        'sites.google.com', 'my.canva.site', 'notion.site', 'framer.website',
        'square.site', 'godaddysites.com', 'jimdosite.com', 'bubbleapps.io',
        'trycloudflare.com', 'ngrok.io', 'ngrok-free.app', 'loca.lt',
        'serveo.net', 'azurewebsites.net', 'anvil.app', 'typedream.app'
    ];

    /*
     * Dynamic DNS names point wherever their owner likes, from one minute to
     * the next. Useful at home, and the standard way to run a phishing page
     * off a residential connection.
     */
    var DYNAMIC_DNS = [
        'duckdns.org', 'no-ip.org', 'no-ip.com', 'ddns.net', 'hopto.org',
        'zapto.org', 'sytes.net', 'serveblog.net', 'redirectme.net',
        'myftp.biz', 'myftp.org', 'dynu.net', 'dynv6.net', 'freeddns.org',
        'chickenkiller.com', 'mooo.com', 'cloudns.cl', 'cloudns.nz', 'onthewifi.com'
    ];

    /*
     * Domains that legitimately contain a brand name but are not the brand's
     * main site. Without this list, a page served from amazonaws.com or
     * microsoftonline.com would be reported as impersonating Amazon or
     * Microsoft.
     */
    var OFFICIAL_DOMAINS = [
        'amazonaws.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in',
        'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'amazontrust.com',
        'googleapis.com', 'googleusercontent.com', 'googlesource.com',
        'google.co.uk', 'google.de', 'google.fr', 'google.co.in', 'googleblog.com',
        'microsoftonline.com', 'microsoft.net', 'microsoftstore.com', 'msn.com',
        'live.com', 'office.com', 'office365.com', 'sharepoint.com', 'azure.com',
        'apple.news', 'applecare.com', 'apple.co.uk', 'icloud-content.com',
        'paypalobjects.com', 'paypal.me', 'paypal.co.uk', 'paypal-community.com',
        'fbcdn.net', 'facebook.net', 'instagram.co', 'whatsapp.net',
        'netflix.net', 'nflxvideo.net', 'nflximg.net', 'ebay.co.uk', 'ebayimg.com',
        'linkedin.cn', 'licdn.com', 'dropboxusercontent.com', 'dropboxstatic.com',
        'binance.us', 'binance.charity', 'coinbase-assets.com', 'steamstatic.com',
        'steamcommunity.com', 'roblox.cn', 'rbxcdn.com', 'discordapp.com',
        'dhl.de', 'dhl.co.uk', 'fedex.co.uk', 'ups.co.uk', 'hsbc.co.uk',
        'barclays.co.uk', 'santander.co.uk', 'chase.co.uk', 'wellsfargomedia.com',
        'revolut.me', 'metamask.io'
    ];

    /* ------------------------------------------- administrator / user list */

    /*
     * Filled from chrome.storage by the content script, so a course tutor or
     * an administrator can add addresses without editing the extension. Each
     * entry is {match: 'host' | '/path substring' | 'https://exact', kind,
     * label, detail}.
     */
    var USER_ENTRIES = [];

    function addEntries(list) {
        if (!list || !list.length) { return USER_ENTRIES.length; }
        list.forEach(function (raw) {
            var entry = typeof raw === 'string' ? {match: raw} : raw;
            if (!entry || !entry.match) { return; }
            USER_ENTRIES.push({
                match: String(entry.match).toLowerCase(),
                kind: entry.kind || 'blocked',
                label: entry.label || 'Address on the local block list',
                detail: entry.detail || 'This address was added to the local block list.'
            });
        });
        return USER_ENTRIES.length;
    }

    function clearEntries() { USER_ENTRIES.length = 0; }

    function matchUserEntry(url, host, href) {
        for (var i = 0; i < USER_ENTRIES.length; i++) {
            var entry = USER_ENTRIES[i];
            if (entry.match.indexOf('://') !== -1) {
                if (href.indexOf(entry.match) === 0) { return entry; }
            } else if (entry.match.charAt(0) === '/') {
                if ((url.pathname + url.search).toLowerCase().indexOf(entry.match) !== -1) { return entry; }
            } else if (endsWithHost(host, entry.match)) {
                return entry;
            }
        }
        return null;
    }

    /* --------------------------------------------------------------- lookup */

    /**
     * Is this address on one of the bundled lists?
     * @returns {null|Object} {kind, label, detail, source, severity}
     */
    function lookup(url) {
        if (!url || !url.hostname) { return null; }
        var host = hostOf(url);
        var domain = registrable(host);
        var path = String(url.pathname || '') + String(url.search || '');
        var href = String(url.href || '').toLowerCase();

        var user = matchUserEntry(url, host, href);
        if (user) {
            return {
                kind: user.kind, label: user.label, detail: user.detail,
                source: 'Local block list', severity: 'block'
            };
        }

        if (domain === 'amtso.org' && AMTSO_PATH.test(path)) {
            var amtso = amtsoKind(path);
            return {
                kind: amtso.kind,
                label: amtso.label,
                detail: 'This is a published test page. It is harmless in itself, and it is only ' +
                        'reachable when the protection it tests is switched off or missing - which ' +
                        'is what the page itself says when it loads.',
                source: 'AMTSO feature settings check',
                severity: 'block'
            };
        }

        for (var i = 0; i < TEST_RESOURCES.length; i++) {
            var res = TEST_RESOURCES[i];
            if (endsWithHost(host, res.host) && res.path.test(path)) {
                return {
                    kind: res.kind, label: res.label, detail: res.detail,
                    source: 'Published security test resource', severity: 'block'
                };
            }
        }

        return null;
    }

    /** Wording that identifies a page whose purpose is to be blocked. */
    function matchPageSignature(text) {
        var hay = String(text || '').toLowerCase();
        if (hay.length < 40) { return null; }
        for (var i = 0; i < TEST_PAGE_SIGNATURES.length; i++) {
            var sig = TEST_PAGE_SIGNATURES[i];
            var hits = sig.phrases.filter(function (phrase) { return hay.indexOf(phrase) !== -1; });
            if (hits.length === sig.phrases.length) {
                return {
                    kind: sig.kind, label: sig.label, phrase: hits[0],
                    source: 'Test page wording', severity: 'block'
                };
            }
        }
        return null;
    }

    function exfilEndpoints(source) {
        var text = String(source || '');
        var found = [];
        EXFIL_ENDPOINTS.forEach(function (endpoint) {
            if (found.length < 4 && endpoint.pattern.test(text)) {
                found.push({name: endpoint.name, severity: endpoint.severity});
            }
        });
        return found;
    }

    function kitPaths(path) {
        var found = [];
        KIT_PATHS.forEach(function (kit) {
            if (found.length < 3 && kit.pattern.test(path)) { found.push(kit.name); }
        });
        return found;
    }

    function freeHost(host) {
        var name = String(host).toLowerCase();
        for (var i = 0; i < FREE_HOSTS.length; i++) {
            if (endsWithHost(name, FREE_HOSTS[i]) && name !== FREE_HOSTS[i]) { return FREE_HOSTS[i]; }
        }
        return null;
    }

    function dynamicDns(host) {
        var name = String(host).toLowerCase();
        for (var i = 0; i < DYNAMIC_DNS.length; i++) {
            if (endsWithHost(name, DYNAMIC_DNS[i]) && name !== DYNAMIC_DNS[i]) { return DYNAMIC_DNS[i]; }
        }
        return null;
    }

    function isOfficialDomain(domain) {
        return OFFICIAL_DOMAINS.indexOf(String(domain).toLowerCase()) !== -1;
    }

    return {
        version: FEED_VERSION,
        lookup: lookup,
        matchPageSignature: matchPageSignature,
        exfilEndpoints: exfilEndpoints,
        kitPaths: kitPaths,
        freeHost: freeHost,
        dynamicDns: dynamicDns,
        isOfficialDomain: isOfficialDomain,
        addEntries: addEntries,
        clearEntries: clearEntries,
        userEntryCount: function () { return USER_ENTRIES.length; },
        eicarSignature: EICAR_SIGNATURE,
        officialDomains: OFFICIAL_DOMAINS,
        freeHosts: FREE_HOSTS,
        dynamicDnsHosts: DYNAMIC_DNS
    };
}));
