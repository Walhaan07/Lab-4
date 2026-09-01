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

    var FEED_VERSION = '2026.09.02';

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
     * A security product is measured against test pages: harmless pages that
     * a working filter is supposed to stop you reaching. AMTSO publishes a
     * set, so do Google, Mozilla, WICAR and EICAR, and so does any vendor who
     * wants customers to be able to check their own installation.
     *
     * Naming those sites one by one would only ever recognise the ones that
     * existed when this file was written. Both mechanisms below are therefore
     * host-agnostic: a test page is recognised by what its address says it is,
     * and by the fact that the page itself explains that you should not be
     * able to read it.
     */

    /* 1. The address describes a test. Applied to any host, not a list of them. */
    var TEST_URL_PATTERNS = [
        /* strong: these read as the name of the test itself */
        {pattern: /feature[-_]?settings?[-_]?check/i, kind: 'test', strength: 'strong', label: 'feature settings check'},
        {pattern: /security[-_]?features?[-_]?check/i, kind: 'test', strength: 'strong', label: 'security features check'},
        {pattern: /\bcheck[-_](desktop|mobile|android|ios|endpoint|browser|cloud)[-_]/i, kind: 'test', strength: 'strong', label: 'protection feature check'},
        {pattern: /\btestsafebrowsing\b|safe[-_]?browsing[-_](test|check)/i, kind: 'phishing', strength: 'strong', label: 'safe browsing test page'},
        {pattern: /\bits[-_]?a[-_]?trap\b/i, kind: 'phishing', strength: 'strong', label: 'deceptive-site protection test page'},
        {pattern: /\bits[-_]?an[-_]?attack\b/i, kind: 'malware', strength: 'strong', label: 'attack-site protection test page'},
        /* "eicar" names the industry-standard harmless test file rather than a
           company, so an address carrying it is describing its contents. */
        {pattern: /\beicar\b/i, kind: 'malware', strength: 'strong', label: 'EICAR anti-malware test file'},

        /* weak: an article explaining these tests has the same words in its
           address, so on its own this is worth saying and not worth blocking */
        {pattern: /(phishing|malware|spyware|ransomware|adware|virus|pua|potentially[-_]unwanted)[-_](test|check|sample)[-_]?(page|file)?/i,
         kind: 'auto', strength: 'weak', label: 'protection test page'},
        {pattern: /\b(test|testing|check|sample|demo)[-_](phishing|malware|spyware|ransomware|virus|pua|drive[-_]?by)/i,
         kind: 'auto', strength: 'weak', label: 'protection test page'}
    ];

    /* Which protection the test is aimed at, read from the same address. */
    function testKind(text) {
        if (/phish/i.test(text)) { return 'phishing'; }
        if (/pua|potentially[-_]unwanted|adware/i.test(text)) { return 'pua'; }
        if (/malware|virus|ransom|spyware|exploit|drive[-_]?by|compressed|download|eicar|wicar|attack/i.test(text)) { return 'malware'; }
        if (/cloud/i.test(text)) { return 'malware'; }
        return 'test';
    }

    /**
     * Does this address announce itself as a security test page?
     * @returns {null|Object} {kind, label, evidence}
     */
    function classifyTestUrl(url) {
        var subject = String(url.hostname || '') + String(url.pathname || '') + String(url.search || '');
        for (var i = 0; i < TEST_URL_PATTERNS.length; i++) {
            var rule = TEST_URL_PATTERNS[i];
            var match = subject.match(rule.pattern);
            if (match) {
                return {
                    kind: (rule.kind === 'auto' || rule.kind === 'test') ? testKind(subject) : rule.kind,
                    strength: rule.strength,
                    label: 'Address describes a ' + rule.label,
                    evidence: match[0]
                };
            }
        }
        return null;
    }

    /*
     * 2. The page says so itself. Test pages are written to be read by someone
     * whose protection failed, so they explain what they are - in whatever
     * words and language their author chose. Rather than matching one vendor's
     * sentences, three families of wording are scored: what the page claims to
     * be, which protection it is testing, and the giveaway that you were not
     * supposed to get this far.
     */
    var SIGNATURE_FAMILIES = {
        declaration: [
            'test page', 'testing page', 'test file', 'sample page', 'demo page',
            'demonstration page', 'feature settings check', 'security features check',
            'feature check', 'test resource', 'this is a test', 'testpage'
        ],
        protection: [
            'anti-phishing', 'antiphishing', 'anti-malware', 'antimalware', 'anti-virus',
            'antivirus', 'safe browsing', 'safebrowsing', 'phishing protection',
            'malware protection', 'web filter', 'url filter', 'endpoint protection',
            'security software', 'security product', 'security solution', 'web protection',
            'potentially unwanted', 'deceptive site', 'harmful site', 'exploit protection'
        ],
        unblocked: [
            'if you can read this', 'if you can see this', 'if you are reading this',
            'is not enabled', 'not (yet) supporting', 'is not supporting', 'did not block',
            'was not blocked', 'should have been blocked', 'should be blocked',
            'failed to block', 'is disabled or misconfigured', 'or misconfigured',
            'your browser did not', 'nothing stopped you', 'is not working'
        ]
    };

    /*
     * The EICAR signature, split so that the extension's own source file does
     * not trip a desktop scanner while it sits on disk.
     */
    var EICAR_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR' +
                          '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

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
     * Shapes that come from off-the-shelf kits and from the compromised sites
     * they are dropped onto. Deliberately not here: "a long base64-looking
     * value in the query". Every search engine and analytics tag carries one -
     * Google's own ved= parameter matched it - and encoding something is not
     * the same as hiding something.
     */
    var KIT_PATHS = [
        {name: 'PayPal "webscr" clone', pattern: /\/webscr|cmd=_?(login|account|home|update)/i},
        {name: 'kit dropped into a hacked CMS', pattern: /\/wp-(content|includes|admin)\/[^?]*\/(login|signin|verify|secure|account|bank|paypal|office|update)/i},
        /* A folder of nonsense inside WordPress's own directories is what a
           kit leaves behind on a site somebody else broke into. Real uploads
           live under dated folders and have words in their names. */
        {name: 'random folder inside a WordPress install',
         /* Mixed case and digits both: "twentytwenty" is twelve characters of
            ordinary theme name, and the folder a kit unpacks into is not. */
         pattern: /\/wp-(content|includes|admin)\/[a-z0-9-]*\/?(?=[a-zA-Z0-9]*[A-Z])(?=[a-zA-Z0-9]*\d)[a-zA-Z0-9]{12,}\//},
        /* A page buried several folders deep inside WordPress's own
           directories. Those folders hold code and uploads, not pages: what
           is down there is what somebody left behind after breaking in. */
        {name: 'a page buried in a WordPress install', pattern: /\/wp-(content|includes|admin)\/(?!uploads\/)([^/?]+\/){2,}[^/?.]*(\.(html?|php))?\/?$/i},
        {name: 'webmail credential page', pattern: /\/(owa|exchange|webmail|roundcube|cpanel)\/(auth\/)?(logon|login|signin)/i},
        /*
         * A sign-in flow whose handler is a script file.
         *
         * This rule used to ask only whether two sign-in words appeared in
         * the path, one inside the other. That is the shape of nearly every
         * real account area on the web - /accounts/login, /login/verify,
         * /account/security/password - so it reported Instagram, Okta,
         * Dropbox and any bank with a two-step sign-in, and across a corpus
         * of live phishing addresses it identified none of them.
         *
         * What a kit has and a real sign-in flow does not is its own script
         * sitting at the end of that path: a routed application serves
         * /login/verify, an unpacked kit serves /login/verify/next.php.
         */
        {name: 'sign-in flow handled by a dropped script',
         pattern: /\/(?:login|log-in|signin|sign-in|verify|verification|secure|security|account|accounts|update|confirm|password|billing|auth|authenticate|recover|unlock|webscr)[^/?]*\/(?:[^/?]*\/)*?[^/?]*\.(?:php|cgi|pl)(?:[?#]|$)/i},
        {name: 'victim address pre-filled in the link', pattern: /[?&](email|mail|usr|user|login|id)=[^&]*(%40|@)/i},
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
        /* static and app hosting */
        'pages.dev', 'workers.dev', 'r2.dev', 'web.app', 'firebaseapp.com',
        'netlify.app', 'netlify.com', 'vercel.app', 'glitch.me', 'repl.co', 'replit.app',
        'github.io', 'gitlab.io', 'surge.sh', 'onrender.com', 'herokuapp.com',
        'fly.dev', 'railway.app', 'deno.dev', 'val.run', 'laravel.cloud',
        '000webhostapp.com', 'infinityfreeapp.com', 'epizy.com', 'fwh.is', 'byethost.com',
        /* site and page builders */
        'weeblysite.com', 'wixsite.com', 'blogspot.com', 'wordpress.com',
        'sites.google.com', 'my.canva.site', 'notion.site', 'framer.website',
        'framer.app', 'framer.ai', 'square.site', 'godaddysites.com', 'jimdosite.com',
        'bubbleapps.io', 'typedream.app', 'zapier.app', 'webflow.io', 'gitbook.io',
        'carrd.co', 'strikingly.com', 'yolasite.com', 'mystrikingly.com', 'durable.co',
        /* object storage and CDNs that will serve any HTML you upload */
        'blob.core.windows.net', 'azurewebsites.net', 'azurefd.net', 'azureedge.net',
        'linodeobjects.com', 'oortstorages.com', 'backblazeb2.com', 'digitaloceanspaces.com',
        'storage.googleapis.com', 's3.amazonaws.com', 'objectstorage.com',
        /* tunnels and short-lived hosts */
        'trycloudflare.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'loca.lt',
        'serveo.net', 'anvil.app', 'telebit.io', 'localtunnel.me',
        /* form and document hosting that phishing rents by the page */
        'jotform.com', 'form.jotform.com', 'formstack.com', 'typeform.com',
        'sviluppo.host', 'us.cc'
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
     * Is this address one we already know something about?
     * @returns {null|Object} {kind, label, detail, source, severity}
     *   severity 'block'   - certain: the local block list
     *   severity 'suspect' - the address describes a test page, which the page
     *                        content can then confirm or contradict
     */
    function lookup(url) {
        if (!url || !url.hostname) { return null; }
        var host = hostOf(url);
        var href = String(url.href || '').toLowerCase();

        var user = matchUserEntry(url, host, href);
        if (user) {
            return {
                kind: user.kind, label: user.label, detail: user.detail,
                source: 'Local block list', severity: 'block'
            };
        }

        var test = classifyTestUrl(url);
        if (test) {
            return {
                kind: test.kind,
                strength: test.strength,
                label: test.label + ' ("' + test.evidence + '")',
                detail: 'Pages like this are published so that a security product can be verified ' +
                        'against them. They are harmless in themselves, and reaching one means ' +
                        'nothing stopped you.',
                source: 'Address describes a security test page',
                severity: 'suspect',
                evidence: test.evidence
            };
        }

        return null;
    }

    /**
     * Does the page explain that it is a security test page?
     * Two of the three wording families, or the EICAR string, is enough.
     * @returns {null|Object} {kind, label, phrase, families, severity}
     */
    function matchPageSignature(text) {
        var hay = String(text || '').toLowerCase();
        if (hay.length < 30) { return null; }

        if (hay.indexOf(EICAR_SIGNATURE.toLowerCase()) !== -1) {
            return {
                kind: 'malware',
                label: 'EICAR anti-malware test string',
                phrase: 'the EICAR test signature',
                families: ['eicar'],
                source: 'The page carries the EICAR test signature',
                severity: 'block'
            };
        }

        var found = {};
        var names = Object.keys(SIGNATURE_FAMILIES);
        names.forEach(function (name) {
            for (var i = 0; i < SIGNATURE_FAMILIES[name].length; i++) {
                var phrase = SIGNATURE_FAMILIES[name][i];
                if (hay.indexOf(phrase) !== -1) { found[name] = phrase; return; }
            }
        });

        var hit = Object.keys(found);
        if (hit.length < 2) { return null; }

        /*
         * What separates a page that IS a test from a page ABOUT one is who
         * it is addressing. A test page talks to you about your protection
         * having failed - "if you can read this", "is not enabled", "did not
         * block". An article explaining such pages never does, because its
         * reader's protection is working perfectly well.
         */
        if (hit.indexOf('unblocked') !== -1) {
            return {
                kind: testKind(hay.slice(0, 4000)),
                label: 'The page says you should not have been able to read it',
                phrase: found.unblocked,
                families: hit,
                source: 'The page says so itself',
                severity: 'block'
            };
        }

        /* Without that, only a short page counts, and only as corroboration
           for an address that already describes a test. Long-form prose about
           anti-phishing testing is an article, whatever words it uses. */
        if (hay.length > 2500) { return null; }
        return {
            kind: testKind(hay.slice(0, 4000)),
            label: 'The page reads like a security feature test',
            phrase: found[hit[0]],
            families: hit,
            source: 'The page reads that way',
            severity: 'suspect'
        };
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
        classifyTestUrl: classifyTestUrl,
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
