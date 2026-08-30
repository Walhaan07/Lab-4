/*
 * spam-analyzer.js  --  Demo 4 (Lab 4)
 * ---------------------------------------------------------------------------
 * Phishing / pharming / scam analyser.
 *
 * Loaded by the extension's content script (window.SpamAnalyzer) and by the
 * Node.js unit tests (require('./spam-analyzer')).
 *
 * Three layers decide the verdict:
 *
 *   1. Reputation   threat-intel.js recognises addresses that are known to be
 *                   dangerous or that exist to be blocked - the published
 *                   anti-phishing feature test pages among them. A heuristic
 *                   can never catch those: they are ordinary, well made pages
 *                   on reputable domains, and every structural test passes.
 *   2. Heuristics   the independent tests below, each one a single question
 *                   about the address, the transport, the forms, the wording
 *                   or the scripts.
 *   3. Correlation  patterns over the findings. Three mild signals that always
 *                   appear together in a credential kit say more than the sum
 *                   of the three, and the PATTERNS table is where that is
 *                   written down.
 *
 * Scoring: every finding adds penalty points, the score is the distance from
 * a fixed points budget (not from the number of tests, so adding a test never
 * dilutes the ones already there), near-conclusive findings cap the score, and
 * a reputation hit blocks outright.
 *
 * NOTE: this is a client side scanner written for a lab exercise. It never
 * contacts a remote blocklist, so its knowledge is only as fresh as the
 * bundled feed, it can produce false positives, and it must not be relied on
 * as somebody's only anti-phishing protection.
 * ---------------------------------------------------------------------------
 */
(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory(require('./threat-intel.js'));      // Node.js unit tests
    } else {
        root.SpamAnalyzer = factory(root.VeriSiteThreatIntel);       // browser + extension
    }
}(typeof self !== 'undefined' ? self : this, function (ThreatIntel) {
    'use strict';

    /* The reputation layer is a separate file, so the analyser keeps working -
       heuristics only - if it ever fails to load. */
    var INTEL = ThreatIntel || {
        version: 'unavailable',
        lookup: function () { return null; },
        matchPageSignature: function () { return null; },
        exfilEndpoints: function () { return []; },
        kitPaths: function () { return []; },
        freeHost: function () { return null; },
        dynamicDns: function () { return null; },
        isOfficialDomain: function () { return false; },
        addEntries: function () { return 0; },
        userEntryCount: function () { return 0; }
    };

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

    /* ------------------------------------------------ data added in v2.0 */

    // Which domain each brand actually signs its customers in on.
    var BRAND_SITES = {
        paypal: 'paypal.com', apple: 'apple.com', icloud: 'icloud.com',
        microsoft: 'microsoft.com', office365: 'office.com', outlook: 'outlook.com',
        google: 'google.com', gmail: 'google.com', facebook: 'facebook.com',
        instagram: 'instagram.com', whatsapp: 'whatsapp.com', netflix: 'netflix.com',
        amazon: 'amazon.com', ebay: 'ebay.com', dhl: 'dhl.com', fedex: 'fedex.com',
        ups: 'ups.com', hsbc: 'hsbc.com', barclays: 'barclays.co.uk', chase: 'chase.com',
        wellsfargo: 'wellsfargo.com', citibank: 'citi.com', santander: 'santander.com',
        revolut: 'revolut.com', binance: 'binance.com', coinbase: 'coinbase.com',
        metamask: 'metamask.io', blockchain: 'blockchain.com', steam: 'steampowered.com',
        roblox: 'roblox.com', linkedin: 'linkedin.com', dropbox: 'dropbox.com'
    };

    /*
     * The other domains each brand really runs. Microsoft signs people in on
     * live.com, Amazon serves from amazonaws.com, PayPal's images come from
     * paypalobjects.com. Without this, outlook.live.com reads as "the word
     * outlook on a domain that is not outlook.com" - which is exactly the
     * shape of a phishing host, and exactly wrong here.
     */
    var BRAND_OWNED = {
        paypal: ['paypal.com', 'paypalobjects.com', 'paypal.me', 'paypal.co.uk', 'paypal-community.com'],
        apple: ['apple.com', 'icloud.com', 'apple.news', 'applecare.com', 'icloud-content.com', 'itunes.com'],
        icloud: ['icloud.com', 'apple.com', 'icloud-content.com'],
        microsoft: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com',
                    'msn.com', 'outlook.com', 'sharepoint.com', 'azure.com', 'microsoft.net',
                    'microsoftstore.com', 'windows.com', 'skype.com', 'bing.com', 'xbox.com'],
        office365: ['office.com', 'office365.com', 'microsoft.com', 'microsoftonline.com', 'live.com', 'sharepoint.com'],
        outlook: ['outlook.com', 'live.com', 'office.com', 'microsoft.com', 'microsoftonline.com', 'hotmail.com'],
        google: ['google.com', 'googleapis.com', 'googleusercontent.com', 'gmail.com', 'youtube.com',
                 'googlesource.com', 'goo.gl', 'withgoogle.com', 'google.co.uk', 'blogger.com'],
        gmail: ['gmail.com', 'google.com', 'googlemail.com'],
        facebook: ['facebook.com', 'fbcdn.net', 'facebook.net', 'meta.com', 'messenger.com', 'fb.com'],
        instagram: ['instagram.com', 'cdninstagram.com', 'facebook.com', 'meta.com'],
        whatsapp: ['whatsapp.com', 'whatsapp.net', 'meta.com', 'facebook.com'],
        netflix: ['netflix.com', 'nflximg.net', 'nflxvideo.net', 'nflxext.com'],
        amazon: ['amazon.com', 'amazonaws.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.in',
                 'amazon.ca', 'amazon.com.au', 'amazon.co.jp', 'media-amazon.com', 'ssl-images-amazon.com',
                 'primevideo.com', 'audible.com'],
        ebay: ['ebay.com', 'ebay.co.uk', 'ebayimg.com', 'ebaystatic.com'],
        dhl: ['dhl.com', 'dhl.de', 'dhl.co.uk', 'dpdhl.com'],
        fedex: ['fedex.com', 'fedex.co.uk'],
        ups: ['ups.com', 'ups.co.uk'],
        hsbc: ['hsbc.com', 'hsbc.co.uk', 'hsbc.ca', 'hsbcnet.com'],
        barclays: ['barclays.co.uk', 'barclays.com', 'barclaycard.co.uk'],
        chase: ['chase.com', 'chase.co.uk', 'jpmorgan.com'],
        wellsfargo: ['wellsfargo.com', 'wellsfargomedia.com'],
        citibank: ['citi.com', 'citibank.com', 'citigroup.com'],
        santander: ['santander.com', 'santander.co.uk', 'santanderbank.com'],
        revolut: ['revolut.com', 'revolut.me'],
        binance: ['binance.com', 'binance.us', 'bnbstatic.com'],
        coinbase: ['coinbase.com', 'coinbase-assets.com', 'cbhq.net'],
        metamask: ['metamask.io', 'consensys.net'],
        blockchain: ['blockchain.com', 'blockchain.info'],
        steam: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'valvesoftware.com'],
        roblox: ['roblox.com', 'rbxcdn.com'],
        linkedin: ['linkedin.com', 'licdn.com'],
        dropbox: ['dropbox.com', 'dropboxusercontent.com', 'dropboxstatic.com']
    };

    // Words that only make sense if the page wants a wallet's recovery phrase.
    var SEED_PHRASE_WORDS = [
        'seed phrase', 'secret recovery phrase', 'recovery phrase', 'mnemonic phrase',
        'twelve word', '12-word', '12 word phrase', '24-word', 'backup phrase',
        'private key', 'keystore file', 'wallet passphrase', 'import your wallet'
    ];

    // Wallet calls a drainer needs: connect, then sign away the contents.
    var DRAINER_METHODS = [
        'eth_requestaccounts', 'personal_sign', 'eth_signtypeddata', 'eth_sign',
        'setapprovalforall', 'increaseallowance', 'approve(', 'transferfrom(',
        'walletconnect', 'signalltransactions', 'signandsendtransaction'
    ];

    /*
     * "ClickFix": the page pretends to be a CAPTCHA and talks the visitor into
     * running a command themselves, which side-steps every download warning
     * the browser has.
     */
    var CLICKFIX_PHRASES = [
        'press windows + r', 'windows key + r', 'win + r', 'press ctrl + v',
        'open powershell', 'paste it into', 'press enter to verify',
        'verify you are human by', 'run the command', 'terminal window',
        'i am not a robot' 
    ];

    var CLIPBOARD_CALLS = ['navigator.clipboard.writetext', 'document.execcommand(\'copy\')',
                           'document.execcommand("copy")', 'clipboarddata.setdata'];

    // Payment methods that cannot be reversed once handed over.
    var GIFT_CARD_PHRASES = [
        'gift card code', 'itunes card', 'google play card', 'steam wallet code',
        'amazon gift card', 'scratch the back', 'send the code', 'voucher code to',
        'apple gift card', 'prepaid card code'
    ];

    var GIVEAWAY_PHRASES = [
        'send 0.', 'send 1 btc', 'double your', 'get back twice', 'x2 your',
        'giveaway is live', 'first 1000 participants', 'send eth receive',
        'multiply your crypto', 'return double'
    ];

    var INVESTMENT_PHRASES = [
        'guaranteed profit', 'guaranteed return', 'guaranteed daily', 'roi daily',
        'risk-free investment', 'passive income guaranteed', 'withdraw anytime',
        'trading bot profit', 'signal group profit', '% daily'
    ];

    var SURVEY_PHRASES = [
        'you have been selected', 'spin the wheel', 'claim your reward',
        'complete this survey', 'you are today\'s lucky', 'congratulations, you are the',
        'select a gift below', 'you are the winner of'
    ];

    var FAKE_UPDATE_PHRASES = [
        'your browser is out of date', 'update your browser to continue',
        'flash player is out of date', 'chrome update required', 'critical update required',
        'your version is outdated', 'install the update to continue', 'driver update required'
    ];

    var FAKE_CAPTCHA_PHRASES = [
        'click allow to verify', 'press allow to continue', 'allow to confirm you are not a robot',
        'click allow if you are not a robot', 'tap allow to continue', 'allow notifications to verify'
    ];

    // Security badges a page can claim without ever being audited.
    var SECURITY_SEALS = [
        'norton secured', 'mcafee secure', 'verified by visa', 'trustwave secured',
        'ssl secured', 'secured by ssl', '100% secure checkout', 'digicert secured',
        'godaddy verified', 'bbb accredited'
    ];

    // Vendors whose seal images must come from the vendor's own domain.
    var SEAL_DOMAINS = ['norton.com', 'mcafee.com', 'digicert.com', 'trustwave.com',
                        'visa.com', 'bbb.org', 'godaddy.com', 'sectigo.com', 'truste.com'];

    var OTP_HINTS = ['one-time code', 'one time code', 'verification code', 'security code',
                     'authentication code', '2fa code', 'two-factor', 'sms code', 'otp',
                     'authenticator app code'];

    var ID_DOCUMENT_WORDS = ['passport', 'driving licence', 'driver license', 'driver\'s license',
                             'id card photo', 'selfie with', 'proof of identity', 'national id',
                             'upload your id', 'photo of your id'];

    // Scripts that hide the page from anything that is not a human visitor.
    var CLOAKING_TOKENS = ['navigator.webdriver', 'googlebot', 'bingbot', 'phantomjs',
                           'headlesschrome', 'crawler', 'spider', '/bot|crawl|spider/'];

    // Scripts that try to keep the page away from developer tools.
    var DEVTOOLS_TOKENS = ['contextmenu', 'keycode==123', 'keycode === 123', 'e.keycode==123',
                           'devtools', 'debugger;', 'ctrlkey&&e.keycode==85', 'disable right click',
                           'oncontextmenu'];

    var DNS_CHANGE_PHRASES = ['change your dns', 'set your dns to', 'dns server address',
                              'update your router settings', 'router configuration required',
                              'enter your router password', 'admin password of your router'];

    // Administration paths on the sort of home router a pharming attack rewrites.
    var ROUTER_PATHS = ['/cgi-bin/luci', '/hnap1', '/setup.cgi', '/apply.cgi', '/tmunblock.cgi',
                        '/dnscfg.cgi', '/goform/', '/userrpm/', '/cgi-bin/webproc'];

    var GATEWAY_IPS = ['192.168.0.1', '192.168.1.1', '192.168.1.254', '192.168.100.1',
                       '10.0.0.1', '10.0.0.138', '10.1.1.1', '172.16.0.1'];

    // RFC1918 / loopback / link-local, i.e. addresses that only exist inside a network.
    var PRIVATE_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/;

    var SUPPORT_NUMBER = /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?){2}\d{4}|\b1[\s.-]?8(?:00|55|66|77|88)[\s.-]?\d{3}[\s.-]?\d{4}\b/;

    // Files a page can offer that install something rather than show something.
    var INSTALL_EXT = ['.apk', '.mobileconfig', '.msix', '.appx', '.pkg', '.deb', '.crx', '.xpi'];

    var ARCHIVE_EXT = ['.zip', '.rar', '.7z', '.iso', '.img', '.gz', '.cab', '.ace'];

    /*
     * Pages whose visible words are written by whoever is using them, not by
     * the site. Typing "congratulations you won a free gift card" into an
     * assistant, or searching for it, must not make the assistant look like a
     * scam - the words are the visitor's, and the wording tests have to know
     * the difference between what a page says and what it is merely showing.
     */
    var USER_CONTENT_SITES = [
        {kind: 'assistant', hosts: ['chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
                                    'gemini.google.com', 'bard.google.com', 'copilot.microsoft.com',
                                    'perplexity.ai', 'poe.com', 'character.ai', 'huggingface.co',
                                    'deepseek.com', 'mistral.ai', 'you.com', 'phind.com', 'grok.com',
                                    'x.ai', 'meta.ai', 'pi.ai', 'lmarena.ai', 'chatbotui.com']},
        {kind: 'search', hosts: ['google.com', 'google.co.uk', 'bing.com', 'duckduckgo.com',
                                 'search.yahoo.com', 'yahoo.com', 'ecosia.org', 'startpage.com',
                                 'qwant.com', 'baidu.com', 'yandex.com', 'brave.com', 'searx.be',
                                 'ask.com', 'mojeek.com']},
        {kind: 'mail', hosts: ['mail.google.com', 'outlook.com', 'outlook.live.com', 'outlook.office.com',
                               'live.com', 'mail.yahoo.com', 'proton.me', 'protonmail.com',
                               'zoho.com', 'mail.com', 'fastmail.com', 'gmx.com', 'roundcube.net']},
        {kind: 'social', hosts: ['x.com', 'twitter.com', 'facebook.com', 'instagram.com',
                                 'reddit.com', 'linkedin.com', 'tiktok.com', 'youtube.com',
                                 'threads.net', 'bsky.app', 'mastodon.social', 'discord.com',
                                 'telegram.org', 'web.whatsapp.com', 'pinterest.com', 'tumblr.com',
                                 'snapchat.com', 'twitch.tv', 'vk.com', 'weibo.com']},
        {kind: 'community', hosts: ['stackoverflow.com', 'stackexchange.com', 'superuser.com',
                                    'serverfault.com', 'askubuntu.com', 'quora.com', 'medium.com',
                                    'substack.com', 'wikipedia.org', 'wikimedia.org', 'github.com',
                                    'gitlab.com', 'bitbucket.org', 'notion.so', 'docs.google.com',
                                    'drive.google.com', 'slack.com', 'teams.microsoft.com',
                                    'trello.com', 'atlassian.net', 'hackernews.com', 'ycombinator.com',
                                    'discourse.org', 'forums.mozilla.org']},
        {kind: 'marketplace', hosts: ['amazon.com', 'amazon.co.uk', 'ebay.com', 'ebay.co.uk',
                                      'etsy.com', 'aliexpress.com', 'trustpilot.com', 'yelp.com',
                                      'tripadvisor.com', 'booking.com', 'gumtree.com', 'craigslist.org']}
    ];

    /*
     * Regions of a page that hold what the visitor typed or what another
     * visitor wrote. Their text is removed before the wording tests read the
     * page, so a search box, a chat composer or a quoted message can never be
     * mistaken for the site's own claims.
     */
    var USER_REGION_SELECTOR = [
        'input', 'textarea', 'select', 'option',
        '[contenteditable="true"]', '[contenteditable=""]', '[role="textbox"]',
        '[role="searchbox"]', '[role="combobox"]', '[role="log"]',
        '.ProseMirror', '.CodeMirror', '.monaco-editor', '.ql-editor',
        '[data-message-author-role]', '[data-testid*="conversation"]',
        '[class*="message-content"]', '[class*="chat-message"]',
        '[class*="user-message"]'
    ].join(', ');

    /*
     * Quotes, comments, reviews and code blocks belong to other people - but
     * only on a page that hosts other people's writing. Ignoring them
     * everywhere would hand any scam page a way through: wrap the pitch in
     * <blockquote> and the wording tests would never read it.
     */
    var QUOTED_REGION_SELECTOR = [
        'blockquote', 'code', 'pre', '[class*="comment-body"]', '[id*="comment"]',
        '[class*="review-text"]', '[class*="quote"]'
    ].join(', ');

    // Query parameters that carry whatever the visitor asked for.
    var QUERY_PARAMS = ['q', 'query', 's', 'search', 'search_query', 'k', 'p', 'text',
                        'prompt', 'question', 'wd', 'keyword', 'keywords'];

    /*
     * Scoring constants. The score is the distance from a fixed points budget
     * rather than from the total weight of the test suite: adding a test must
     * make the scanner sharper, never gentler on the pages it already caught.
     */
    var RISK_POINTS_PAGE = 60;      // points that take a full page scan to zero
    var RISK_POINTS_URL = 35;       // ... and an address-only scan, which has fewer signals
    var HYGIENE_BUDGET = 12;        // most a page can lose for nuisance-only findings

    /*
     * Findings that describe a badly behaved page rather than a dangerous one.
     * A news site with eight ad slots and no contact link is annoying, not a
     * threat, so those findings share a small budget and cannot by themselves
     * push an honest site out of the safe band.
     */
    var HYGIENE_CHECKS = {
        'third-party-scripts': true, 'ad-density': true, 'contact-info': true,
        'external-links': true, 'shouty-text': true, 'hidden-text': true,
        'overlay-ads': true, 'query-complexity': true, 'permission-abuse': true,
        'subscription-trap': true, 'site-identity': true, 'hidden-iframes': true,
        'popup-traps': true, 'redirect-chain': true, 'free-subdomain-host': true
    };

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

    /* --------------------------------------------------- helpers added in v2.0 */

    /** Source of every inline <script> on the page, capped for speed. */
    function inlineScriptSource(doc) {
        var code = '';
        try {
            var tags = doc.querySelectorAll('script:not([src])');
            for (var i = 0; i < tags.length && code.length < 200000; i++) {
                code += (tags[i].textContent || '') + '\n';
            }
            // Inline handlers hide the same behaviour in an attribute.
            var handlers = doc.querySelectorAll('[onclick], [onload], [onsubmit], [oncontextmenu], [onkeydown]');
            for (var j = 0; j < handlers.length && code.length < 220000; j++) {
                ['onclick', 'onload', 'onsubmit', 'oncontextmenu', 'onkeydown'].forEach(function (name) {
                    var value = handlers[j].getAttribute(name);
                    if (value) { code += value + '\n'; }
                });
            }
        } catch (e) { /* hostile document - what we have is enough */ }
        return code.slice(0, 220000);
    }

    /** The page's own markup, capped, for tests that need attributes as text. */
    function pageMarkup(doc) {
        try {
            var root = doc.documentElement || doc.body;
            return (root && root.outerHTML ? root.outerHTML : (doc.body ? doc.body.innerHTML : '')).slice(0, 300000);
        } catch (e) {
            return '';
        }
    }

    /** Does this domain legitimately belong to the brand? */
    function brandOwnsDomain(brand, domain) {
        if (!domain) { return false; }
        var owned = BRAND_OWNED[brand];
        if (owned && owned.indexOf(domain) !== -1) { return true; }
        if (BRAND_SITES[brand] === domain) { return true; }
        /* Country sites the lists above cannot enumerate: the brand is the
           whole first label of a domain the feed already knows is official. */
        return domain.split('.')[0] === brand && INTEL.isOfficialDomain(domain);
    }

    /**
     * Which brands the page presents itself as - title, main heading, the
     * site name it declares to social networks, its logo, and the copyright
     * line. Brands the domain legitimately owns are removed, so what is left
     * is a page wearing somebody else's name.
     */
    function claimedBrands(c) {
        var claim = ' ' + (c.doc.title || '') + ' ';
        try {
            var heading = c.doc.querySelector('h1');
            if (heading) { claim += (heading.textContent || '') + ' '; }
            var meta = c.doc.querySelector('meta[property="og:site_name"], meta[name="application-name"], meta[name="author"]');
            if (meta) { claim += (meta.getAttribute('content') || '') + ' '; }
            var logo = c.doc.querySelector('img[alt], img[src*="logo"], [class*="logo"] img');
            if (logo) { claim += (logo.getAttribute('alt') || '') + ' ' + (logo.getAttribute('src') || '') + ' '; }
        } catch (e) { /* ignore */ }
        // The copyright line is the last thing a cloned page remembers to change.
        var tail = c.text.slice(-3000);
        var copyright = tail.match(/(?:©|\(c\)|copyright)[^\n]{0,60}/gi);
        if (copyright) { claim += copyright.join(' '); }

        return countOccurrences(claim.toLowerCase(), BRANDS).filter(function (brand) {
            return !brandOwnsDomain(brand, c.domain) && c.domain.indexOf(brand) === -1;
        });
    }

    /** An address that only exists inside somebody's own network. */
    function isPrivateHost(host) {
        var name = String(host).replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
        return PRIVATE_IP.test(name) || isLocalAddress(name) || /\.(local|internal|lan|home|localdomain)$/.test(name);
    }

    function resolveUrl(value, base) {
        try {
            return new URL(value, base);
        } catch (e) {
            return null;
        }
    }

    /** Every URL the page points at: links, forms, scripts, frames, images. */
    function referencedUrls(doc, base, limit) {
        var out = [];
        var selectors = ['a[href]', 'form[action]', 'script[src]', 'iframe[src]', 'img[src]', 'link[href]'];
        try {
            selectors.forEach(function (selector) {
                var nodes = doc.querySelectorAll(selector);
                for (var i = 0; i < nodes.length && out.length < limit; i++) {
                    var raw = nodes[i].getAttribute('href') || nodes[i].getAttribute('src') ||
                              nodes[i].getAttribute('action');
                    if (!raw || /^(#|javascript:|data:|mailto:|tel:)/i.test(raw)) { continue; }
                    var url = resolveUrl(raw, base);
                    if (url) { out.push(url); }
                }
            });
        } catch (e) { /* ignore */ }
        return out;
    }

    /* Four tests want the same list, and walking a large page four times is
       four times the cost for the same answer. */
    function pageRefs(c) {
        if (!c.refs) { c.refs = c.doc ? referencedUrls(c.doc, c.href, 300) : []; }
        return c.refs;
    }

    /** Input fields whose name, id, placeholder or label suggests a purpose. */
    function fieldsMatching(doc, words) {
        var hits = [];
        try {
            var inputs = doc.querySelectorAll('input, textarea, select');
            for (var i = 0; i < inputs.length && hits.length < 5; i++) {
                var input = inputs[i];
                var hay = [input.getAttribute('name'), input.getAttribute('id'),
                           input.getAttribute('placeholder'), input.getAttribute('aria-label'),
                           input.getAttribute('autocomplete')].join(' ').toLowerCase();
                for (var j = 0; j < words.length; j++) {
                    if (hay.indexOf(words[j]) !== -1) { hits.push(words[j]); break; }
                }
            }
        } catch (e) { /* ignore */ }
        return hits;
    }

    /* ------------------------------------------- who wrote the words here */

    /**
     * Split the page's visible text into what the site says and what its
     * visitors put there. Everything the wording tests read comes from the
     * first of the two.
     */
    function splitAuthorship(doc, url, userDriven) {
        var site = visibleText(doc);
        var user = [];
        var selector = USER_REGION_SELECTOR + (userDriven ? ', ' + QUOTED_REGION_SELECTOR : '');

        try {
            var regions = doc.querySelectorAll(selector);
            for (var i = 0; i < regions.length && user.length < 60; i++) {
                var node = regions[i];
                var chunk = node.value || node.innerText || node.textContent || '';
                chunk = String(chunk).replace(/\s+/g, ' ').trim();
                if (chunk.length >= 3 && chunk.length <= 20000) { user.push(chunk); }
            }
        } catch (e) { /* ignore */ }

        // What the visitor searched for or asked, straight out of the address.
        try {
            QUERY_PARAMS.forEach(function (name) {
                var value = url && url.searchParams ? url.searchParams.get(name) : null;
                if (value && value.length >= 3) { user.push(value.replace(/\+/g, ' ')); }
            });
        } catch (e) { /* ignore */ }

        // Remove each of those passages from the site's own copy.
        user.forEach(function (chunk) {
            if (chunk.length < 3 || site.length > 400000) { return; }
            if (site.indexOf(chunk) !== -1) { site = site.split(chunk).join(' '); }
        });

        return {site: site, user: user.join(' \n ').slice(0, 60000)};
    }

    /** Does the page look like a conversation, a feed or a set of results? */
    function looksUserDriven(doc) {
        try {
            var composer = doc.querySelector('textarea, [contenteditable="true"], [role="textbox"], input[type="search"], input[name="q"]');
            if (!composer) { return false; }
            var conversation = doc.querySelector('[data-message-author-role], [role="log"], [role="feed"], ' +
                                                 '[class*="conversation"], [class*="chat"], [class*="thread"], ' +
                                                 '[class*="results"], [id*="results"], [class*="timeline"]');
            return !!conversation;
        } catch (e) {
            return false;
        }
    }

    /**
     * What kind of page is this, and can its wording be taken as its own?
     * A search engine showing a scam in its results is not a scam; a page that
     * writes the same words itself is a different matter entirely.
     */
    function pageContext(host, domain, doc) {
        var context = {kind: null, userDriven: false, reason: ''};
        var name = String(host).toLowerCase();

        for (var i = 0; i < USER_CONTENT_SITES.length; i++) {
            var group = USER_CONTENT_SITES[i];
            for (var j = 0; j < group.hosts.length; j++) {
                var known = group.hosts[j];
                if (name === known || name.slice(-(known.length + 1)) === '.' + known || domain === known) {
                    context.kind = group.kind;
                    context.userDriven = true;
                    context.reason = 'This is a ' + group.kind + ' page: the words on screen are written by ' +
                                     'the people using it, so they are not read as claims made by the site.';
                    return context;
                }
            }
        }

        if (doc && looksUserDriven(doc)) {
            context.kind = 'interactive';
            context.userDriven = true;
            context.reason = 'The page is a conversation, feed or results list, so its visible words come ' +
                             'from the people using it rather than from the site itself.';
        }
        return context;
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
            about: 'Without HTTPS everything you type travels in plain text, so anyone sharing the ' +
                   'network - a cafe hotspot, the building\'s router - can read it or change the ' +
                   'page on its way to you. Encryption also proves you reached the real server ' +
                   'rather than one pretending to be it. There is no longer a good reason for a ' +
                   'public site to go without it.',
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
            about: 'Real sites almost always have a domain name, because a name is what customers ' +
                   'remember and what a company registers. A bare IP address usually means a ' +
                   'machine set up quickly and anonymously, or a legitimate machine that has been ' +
                   'taken over and is being used to host something else.',
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
            about: 'Domain names may contain non-English characters, which are stored in an ' +
                   'encoded form starting with xn--. That is completely normal for international ' +
                   'sites, but the same mechanism lets a name be built from letters that only look ' +
                   'like English ones, so the check shows you what the address really spells.',
            title: 'Domain is plain ASCII',
            failTitle: 'Domain uses international characters',
            category: 'URL',
            /* Small on purpose. An international domain is ordinary, and the
               spoofs are caught by mixed-scripts and homograph-brand, which
               look at what the name actually spells. */
            weight: 3,
            run: function (c) {
                if (c.host.indexOf('xn--') === -1) { return null; }
                return 'The domain is stored as "' + c.host + '" and displays as "' +
                       c.decodedHost + '". Check that it reads the way you expect.';
            }
        },
        {
            id: 'at-symbol',
            about: 'Everything before an @ in a web address is treated as a user name and ignored ' +
                   'when the browser decides which server to contact. That lets an attacker put a ' +
                   'trusted name on the left and their own server on the right, so a quick glance ' +
                   'reads as the real site while the connection goes elsewhere.',
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
            about: 'A shortened link hides where it goes until you have already arrived, so you ' +
                   'cannot judge the destination before the page loads. That is convenient in a ' +
                   'message with a character limit, and it is also why shorteners are used to slip ' +
                   'past spam filters and to disguise phishing pages.',
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
            about: 'Some domain endings are free or nearly free, with little checking of who ' +
                   'registers them. Established organisations rarely use them, while spam ' +
                   'campaigns like them precisely because a domain that costs nothing can be ' +
                   'abandoned the moment it is blocked and replaced the same day.',
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
            about: 'A well known company\'s name appears in the address, but not in the part that ' +
                   'decides who owns it. Anyone can put a brand in a sub-domain or a path; only ' +
                   'the registrable domain - the bit immediately before the first single slash - ' +
                   'actually proves who is running the site.',
            title: 'No brand name used outside the real domain',
            failTitle: 'Brand name used outside the real domain',
            category: 'URL',
            weight: 12,
            run: function (c) {
                /* "Not in the domain" is not the same as "not the owner":
                   outlook.live.com and s3.amazonaws.com are the companies
                   themselves, on a domain that does not spell their name. */
                var notInDomain = function (brand) {
                    return c.domain.indexOf(brand) === -1 && !brandOwnsDomain(brand, c.domain);
                };
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
            about: 'Every dot adds another level to the name, and a long chain pushes the real ' +
                   'domain out of view, especially in a phone\'s narrow address bar. Genuine sites ' +
                   'seldom need more than two or three levels, so a deep chain is often there to ' +
                   'bury the part that identifies the owner.',
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
            about: 'A very long address is hard to read, and on a small screen the end of it ' +
                   'simply is not shown. Padding a URL with filler is a standard way to push the ' +
                   'real domain past the edge of the address bar so you never see it.',
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
            about: 'A string of hyphens is a typosquatting pattern - names like ' +
                   'secure-login-account-verify are assembled to look reassuring. A real brand ' +
                   'normally owns a short domain and does not need to spell out its reassurances ' +
                   'in the name itself.',
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
            about: 'A domain padded with digits usually comes from a bulk registration or an ' +
                   'automatic name generator. Spam and malware networks register hundreds of such ' +
                   'names at once, so that blocking any one of them does not interrupt the ' +
                   'campaign.',
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
            about: 'Words such as login, verify and account in the address are how a page tries to ' +
                   'look official before you have read the domain itself. A genuine sign-in page ' +
                   'usually sits on the company\'s plain domain, and does not need to argue for ' +
                   'its own legitimacy in the URL.',
            title: 'No credential-harvesting keywords in the address',
            failTitle: 'Credential-harvesting keywords in the address',
            category: 'URL',
            weight: 6,
            run: function (c) {
                /* On a company's own domain these words are just the name of
                   the page. accounts.google.com/signin has to say "signin". */
                if (INTEL.isOfficialDomain(c.domain) || BRAND_DOMAINS.indexOf(c.domain) !== -1) { return null; }
                var target = (c.host + c.url.pathname + c.url.search).toLowerCase();
                var hits = countOccurrences(target, SENSITIVE_WORDS);
                return hits.length >= 2
                    ? 'The address contains "' + hits.slice(0, 4).join('", "') + '".'
                    : null;
            }
        },
        {
            id: 'nonstandard-port',
            about: 'Web traffic normally arrives on the standard ports 80 and 443. An unusual port ' +
                   'often means a service running outside a site\'s ordinary setup, which is ' +
                   'common on machines that have been compromised and on temporary infrastructure ' +
                   'put up for a short campaign.',
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
            about: 'Characters in an address can be written as %xx codes, which is normal in small ' +
                   'amounts for spaces and accents. Heavy encoding is different: it is used to ' +
                   'disguise words that a filter would block or that a reader would recognise as ' +
                   'suspicious.',
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
            about: 'A long chain of parameters is not dangerous by itself, but it makes an address ' +
                   'hard to read at a glance, and it is a common place to carry tracking ' +
                   'identifiers or to smuggle a second address inside the first.',
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
            about: 'The address points straight at a program rather than a page, so following it ' +
                   'starts a download instead of showing anything. This is the usual delivery ' +
                   'route for malware sent through links in messages, adverts and fake update ' +
                   'notices.',
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
            about: 'The page is not being served over ordinary web protocols. Schemes such as ' +
                   'data: can carry an entire page inside the address itself, which lets content ' +
                   'run without being hosted anywhere that could be reported or taken down.',
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
            about: 'The name mixes alphabets, or is written entirely in another alphabet whose ' +
                   'letters are drawn like Latin ones. A Cyrillic a is a different character from ' +
                   'a Latin a, so a domain can read exactly like a household brand while belonging ' +
                   'to someone else entirely.',
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
            about: 'The domain is only a character or two away from a well known one - a swapped ' +
                   'letter, a digit standing in for a letter. Names like this are registered ' +
                   'deliberately to catch typing mistakes and glances that do not check the ' +
                   'spelling.',
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
            about: 'A domain ending such as .com appears in the middle of the name, so the address ' +
                   'reads like the real site while the actual domain sits at the end. The owner is ' +
                   'decided by the part immediately before the first single slash, not by whatever ' +
                   'comes earlier.',
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
            about: 'The address carries another address inside it as a parameter. Open redirects ' +
                   'let an attacker borrow a trusted domain for the first hop, so the link looks ' +
                   'safe where it is posted and quietly hands you on to somewhere that is not.',
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
            about: 'The name has the shape of something generated by a program rather than chosen ' +
                   'by a person. Malware and spam networks create such names in bulk, use each for ' +
                   'a few days, and move on before anyone gets around to blocking them.',
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
            about: 'An unusually long host name is hard to take in, and on a phone only the first ' +
                   'part is visible. Length is used deliberately to push the meaningful portion of ' +
                   'the name out of sight.',
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
            about: 'The page asks for a password while the connection is unencrypted, so the ' +
                   'password is sent as readable text. Anyone between you and the site - another ' +
                   'user on the same network, whoever runs it - can capture it, and reused ' +
                   'passwords then open other accounts too.',
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
            about: 'What you type here is delivered to a different site from the one you are ' +
                   'looking at. That is the whole mechanic of a phishing page: a familiar looking ' +
                   'form on screen, someone else\'s server quietly collecting the answers.',
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
            about: 'The page loads other pages invisibly. Hidden frames are used to follow you ' +
                   'between sites, and to float an unseen layer over a button so that your click ' +
                   'does something other than what the visible page suggests.',
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
            about: 'Every external script can do anything the page can, including reading what you ' +
                   'type into it. When code arrives from many different companies, the safety of ' +
                   'the page depends on all of them at once, not only on the site you chose to ' +
                   'visit.',
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
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The wording belongs to unsolicited advertising: prizes, guaranteed income, ' +
                   'miracle cures. Ordinary businesses describe what they sell and what it costs, ' +
                   'while scams lead with reward and urgency because they need a decision before ' +
                   'you think it through.',
            title: 'No classic spam wording in the text',
            failTitle: 'Classic spam wording in the text',
            category: 'Content',
            needsDom: true,
            weight: 15,
            run: function (c) {
                var text = c.text.toLowerCase();
                var strong = countOccurrences(text, SPAM_PHRASES_STRONG);
                var weak = countOccurrences(text, SPAM_PHRASES_WEAK);

                if (strong.length) {
                    return {
                        detail: 'Scam wording found: "' + strong.slice(0, 4).join('", "') + '"' +
                                (weak.length ? ', plus ' + weak.length + ' hard-sell phrase(s).' : '.'),
                        points: clamp(strong.length * 4 + weak.length, 4, 15)
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
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'Blocks of capitals and rows of exclamation marks are the house style of scam ' +
                   'and low quality advertising pages. Established sites write normally, because ' +
                   'shouting costs them the trust they are trying to build.',
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
            about: 'The page\'s own scripts are written to be unreadable, for instance assembling ' +
                   'code from character codes as it runs. Ordinary sites have no reason to hide ' +
                   'what their code does; hiding it is how malicious code gets past scanners and ' +
                   'past anyone who looks.',
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
            about: 'The page moves you somewhere else on its own. Chains of automatic redirects ' +
                   'are used to launder a link, so that the address you clicked and the address ' +
                   'you end up on are not the same and only the first one looked safe.',
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
            about: 'The page is trying to keep you on it: blocking the attempt to leave, opening ' +
                   'extra windows, or disabling the right click menu. Sites that expect you to ' +
                   'come back let you go; this behaviour belongs to pages that need you to stay ' +
                   'while they work on you.',
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
            about: 'Text is in the page but hidden from view, while search engines still read it. ' +
                   'This is keyword stuffing, used to get a page ranked for searches it has ' +
                   'nothing to do with, which is how low quality and scam pages find visitors.',
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
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'Almost every link leads off the site. That is the shape of a link farm - a ' +
                   'page that exists to pass traffic and search ranking elsewhere rather than to ' +
                   'offer anything of its own.',
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
            about: 'The page has no title, icon or description. Everyday sites fill these in ' +
                   'because they decide how the page looks in tabs, bookmarks and search results, ' +
                   'so their absence suggests a page generated in bulk rather than made for ' +
                   'readers.',
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
            about: 'Several floating layers sit on top of the content. Overlays and pop-unders are ' +
                   'used to force adverts that cannot easily be dismissed, and to catch clicks ' +
                   'that were meant for the page underneath.',
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
            about: 'The page offers a program file for download. Paired with urgency - your player ' +
                   'is out of date, your prize is waiting - this is the standard way fake update ' +
                   'and prize pages persuade people to install something themselves.',
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
            about: 'Parts of an otherwise encrypted page are fetched without encryption. Those ' +
                   'parts can be read or swapped out in transit, so a single insecure script can ' +
                   'undo the protection the padlock appears to promise.',
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
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'Countdowns and only-a-few-left notices are designed to stop you weighing the ' +
                   'decision. Manufactured deadlines are a standard pressure technique, used by ' +
                   'outright scams and by aggressive marketing alike.',
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
            about: 'The page collects card or identity details. That is expected at a checkout, ' +
                   'but it is worth noticing when a page asks, and it matters that the connection ' +
                   'is encrypted and that the domain really belongs to the company you think you ' +
                   'are paying.',
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
            about: 'The small icon shown in the browser tab is loaded from another site. A cloned ' +
                   'page often keeps the original\'s branding by linking straight to the ' +
                   'original\'s files, which is a strong sign you are looking at a copy rather ' +
                   'than the real thing.',
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
            about: 'A sign-in page names one company while the domain belongs to someone else. A ' +
                   'real login page for a company is served from that company\'s own domain, so ' +
                   'the two should always agree.',
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
                    return c.domain.indexOf(brand) === -1 && !brandOwnsDomain(brand, c.domain);
                });
                return hits.length
                    ? 'The page presents itself as "' + hits[0] + '" but is served from ' + c.domain + '.'
                    : null;
            }
        },
        {
            id: 'deceptive-links',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The visible text of a link shows one address while the link itself goes to ' +
                   'another. Reading the text is how most people check where a link leads, which ' +
                   'is exactly why this substitution is worth making.',
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
            about: 'Nearly the whole page is another site shown inside a frame. It is a quick way ' +
                   'to clone a site without copying it: the genuine content appears, while the ' +
                   'surrounding page keeps watch over what you type and click.',
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
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page claims your device is infected or locked and presses you to call a ' +
                   'number or act immediately. No web page can inspect your computer, so these ' +
                   'warnings exist to sell fake support, fake fixes, or access to the machine ' +
                   'itself.',
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
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'A crypto wallet address is shown for payment. Such payments cannot be reversed ' +
                   'and are hard to trace, which is why giveaway scams, ransom demands and fake ' +
                   'investment schemes ask for money this way rather than by card.',
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
            about: 'The page requests browser permissions such as notifications or location the ' +
                   'moment it loads, rather than when you do something that needs them. ' +
                   'Notification access in particular is collected so adverts can be pushed to ' +
                   'your desktop long after you have left.',
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
            about: 'The page is dominated by advertising containers. Heavy advertising slows the ' +
                   'page, carries tracking between sites, and is the business model of content ' +
                   'farms, whose pages exist to hold adverts rather than to inform.',
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
            about: 'No contact, about or privacy information could be found. Organisations that ' +
                   'expect to be held to account say who they are and how to reach them, whereas ' +
                   'sites built to be disposable rarely bother.',
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
        },

        /* ------------------------- reputation / known threats (50 - 56) */
        {
            id: 'known-threat',
            about: 'The address itself is known. It matches the bundled list of pages that are ' +
                   'dangerous or that exist purely to be blocked, such as the published tests a ' +
                   'security product is measured against. No amount of reading the markup can ' +
                   'reveal that, which is why the list is consulted first.',
            cap: 6,
            title: 'Address is not on a known-threat list',
            failTitle: 'Address is on a known-threat list',
            category: 'Reputation',
            weight: 25,
            run: function (c) {
                if (!c.intel) { return null; }
                return {
                    detail: c.intel.label + '. ' + c.intel.detail + ' (source: ' + c.intel.source + ')',
                    points: 25,
                    cap: 6
                };
            }
        },
        {
            id: 'test-page-signature',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The wording on the page identifies it as one of the anti-malware feature ' +
                   'tests. Those pages are written to be reached only when protection is off, so ' +
                   'seeing the text at all is the finding. It catches the copies and translations ' +
                   'that the address list has never seen.',
            cap: 10,
            title: 'Page is not a security feature test',
            failTitle: 'Page is a published security feature test',
            category: 'Reputation',
            needsDom: true,
            weight: 20,
            run: function (c) {
                var signature = INTEL.matchPageSignature(c.text + ' ' + (c.doc.title || ''));
                if (!signature) { return null; }
                return {
                    detail: signature.label + ': the page says "' + short(signature.phrase, 60) +
                            '". A filter that was working would have stopped you before this loaded.',
                    points: 20,
                    cap: 10
                };
            }
        },
        {
            id: 'kit-path',
            about: 'The path is one that phishing kits ship with, or one they leave behind on a ' +
                   'site they were dropped onto. A bank keeps its sign-in page somewhere sensible; ' +
                   'a kit unpacked into an upload folder keeps the folder names of whatever it was ' +
                   'unpacked into.',
            title: 'Path is not a known phishing-kit shape',
            failTitle: 'Path matches a known phishing-kit shape',
            category: 'URL',
            weight: 12,
            run: function (c) {
                var hits = INTEL.kitPaths(c.url.pathname + c.url.search);
                if (!hits.length) { return null; }
                return {
                    detail: 'The address matches: ' + hits.join('; ') + '.',
                    points: clamp(6 + hits.length * 3, 6, 12)
                };
            }
        },
        {
            id: 'brand-in-domain',
            about: 'The registrable domain - the part that decides who owns the site - contains a ' +
                   'company\'s name without being that company\'s domain. Anyone can register ' +
                   'apple-billing-support.com; nobody but Apple can register apple.com, which is ' +
                   'the whole reason the ownership is worth checking.',
            cap: 22,
            title: 'Domain does not borrow a company name',
            failTitle: 'Domain borrows a well known company name',
            category: 'URL',
            weight: 16,
            run: function (c) {
                if (!c.domain || INTEL.isOfficialDomain(c.domain)) { return null; }
                var name = c.domain.split('.')[0];
                var hits = countOccurrences(name, BRANDS).filter(function (brand) {
                    if (brandOwnsDomain(brand, c.domain)) { return false; }
                    // The brand must be a separate word, not a fragment of a longer one.
                    var pattern = new RegExp('(^|[^a-z])' + brand + '($|[^a-z])');
                    return pattern.test(name) || name === brand;
                });
                if (!hits.length) { return null; }
                var official = BRAND_SITES[hits[0]] || (hits[0] + '.com');
                return {
                    detail: 'The domain ' + c.domain + ' contains "' + hits[0] + '" but ' + hits[0] +
                            ' signs its customers in on ' + official + '.',
                    points: 16,
                    cap: 22
                };
            }
        },
        {
            id: 'homograph-brand',
            about: 'Written out in plain letters, the domain spells a well known brand. Letters ' +
                   'borrowed from other alphabets are drawn identically to English ones, so the ' +
                   'address in the bar can read as the real company while resolving to a domain ' +
                   'nobody at that company has ever owned.',
            cap: 8,
            title: 'Domain does not spell a brand in look-alike letters',
            failTitle: 'Domain spells a brand in look-alike letters',
            category: 'URL',
            weight: 18,
            run: function (c) {
                if (c.decodedDomain === c.domain && !/[^\x00-\x7F]/.test(c.decodedHost)) { return null; }
                var skeleton = latinSkeleton(c.decodedDomain);
                if (skeleton === c.decodedDomain) { return null; }
                var target = null;
                BRAND_DOMAINS.forEach(function (brandDomain) {
                    if (!target && (skeleton === brandDomain || editDistance(skeleton, brandDomain) <= 1)) {
                        target = brandDomain;
                    }
                });
                if (!target) { return null; }
                return {
                    detail: 'The domain reads as "' + skeleton + '" once look-alike letters are ' +
                            'mapped back, so it is imitating ' + target + '.',
                    points: 18,
                    cap: 8
                };
            }
        },
        {
            id: 'free-subdomain-host',
            about: 'The page sits on a platform that gives away a sub-domain in seconds with no ' +
                   'questions asked. Enormous amounts of honest work is published this way, so on ' +
                   'its own this means little - it matters when the same page also asks for a ' +
                   'password or wears a company\'s branding.',
            title: 'Not published on a throwaway free sub-domain',
            failTitle: 'Published on a throwaway free sub-domain',
            category: 'Reputation',
            weight: 6,
            run: function (c) {
                var platform = INTEL.freeHost(c.host);
                return platform
                    ? 'The site is a free sub-domain of ' + platform + ', which anyone can claim in a minute.'
                    : null;
            }
        },
        {
            id: 'dynamic-dns-host',
            about: 'The name is a dynamic DNS entry, which points wherever its owner sets it and ' +
                   'can be moved between machines at any moment. It is how you reach a computer at ' +
                   'home, and equally how a credential page is run from a laptop that never has to ' +
                   'be registered to anybody.',
            title: 'Not hosted behind a dynamic DNS name',
            failTitle: 'Hosted behind a dynamic DNS name',
            category: 'Reputation',
            weight: 8,
            run: function (c) {
                var provider = INTEL.dynamicDns(c.host);
                return provider
                    ? 'The host is a ' + provider + ' dynamic DNS name, so the machine behind it can change at any time.'
                    : null;
            }
        },
        {
            id: 'credential-in-url',
            about: 'The address carries an e-mail address, a password or a token in its query. ' +
                   'Phishing mail puts the recipient\'s address there so the fake page can greet ' +
                   'them by name and fill the field in for them, which makes the page look like ' +
                   'one they have used before.',
            title: 'No personal identifier in the address',
            failTitle: 'Address carries a personal identifier',
            category: 'URL',
            weight: 8,
            run: function (c) {
                var query = c.url.search.toLowerCase();
                if (!query) { return null; }
                var carriers = ['email=', 'mail=', 'password=', 'passwd=', 'pwd=', 'token=',
                                'session=', 'user=', 'login='];
                var hits = countOccurrences(query, carriers);
                var hasAddress = /%40|@/.test(query);
                if (!hits.length || (!hasAddress && hits.indexOf('password=') === -1 && hits.indexOf('pwd=') === -1)) {
                    return null;
                }
                return 'The link already knows who you are: it carries "' + hits[0] +
                       '" in the query, which is how a phishing page greets you by name.';
            }
        },
        {
            id: 'double-extension',
            about: 'The file name ends in two extensions, so a document icon and a familiar ' +
                   'ending sit in front of something the computer will actually run. Windows ' +
                   'hides the known ending by default, which is precisely the habit this trick ' +
                   'was built around.',
            cap: 30,
            title: 'No disguised file extension',
            failTitle: 'File name hides a second extension',
            category: 'URL',
            weight: 12,
            run: function (c) {
                var name = c.url.pathname.toLowerCase().split('/').pop();
                var match = name.match(/\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|zip|mp4|inv)\.(exe|scr|bat|cmd|com|pif|vbs|js|jar|msi|ps1|lnk)$/);
                return match
                    ? 'The download is named "' + short(name, 40) + '": it looks like a .' + match[1] +
                      ' but it is a .' + match[2] + ', which runs code.'
                    : null;
            }
        },
        {
            id: 'archive-download',
            about: 'The address points straight at an archive or a disc image. Those formats are ' +
                   'used to wrap something up so that the browser and the mail gateway cannot look ' +
                   'inside, and a disc image in particular carries none of the "downloaded from ' +
                   'the internet" marking that would otherwise warn you.',
            title: 'Not a direct archive download',
            failTitle: 'Address is a direct archive download',
            category: 'URL',
            weight: 5,
            run: function (c) {
                var path = c.url.pathname.toLowerCase();
                var hit = ARCHIVE_EXT.filter(function (ext) { return path.slice(-ext.length) === ext; });
                return hit.length
                    ? 'The link downloads a ' + hit[0] + ' archive, which hides its contents from scanners in transit.'
                    : null;
            }
        },

        /* ------------------------- pharming / network integrity (57 - 61) */
        {
            id: 'private-network-target',
            about: 'A public web page is pointing at addresses that only exist inside a private ' +
                   'network. That is what pharming looks like from the inside: the name in the bar ' +
                   'is the one you typed, but the machine answering sits on your own network or ' +
                   'behind a hijacked router rather than at the company.',
            cap: 30,
            title: 'No private network addresses referenced',
            failTitle: 'Page points at private network addresses',
            category: 'Network',
            needsDom: true,
            weight: 14,
            run: function (c) {
                if (isPrivateHost(c.host) || c.url.protocol === 'file:') { return null; }
                var hits = [];
                pageRefs(c).forEach(function (url) {
                    if (hits.length < 3 && isPrivateHost(url.hostname)) { hits.push(url.hostname); }
                });
                if (!hits.length) { return null; }
                return {
                    detail: 'A public page is loading from or posting to ' + hits.join(', ') +
                            ', an address that only exists inside a local network.',
                    points: clamp(8 + hits.length * 3, 8, 14)
                };
            }
        },
        {
            id: 'router-attack',
            about: 'The page is talking to a home router\'s administration interface. A page you ' +
                   'merely visit can send requests to the box in the corner of the room, and if it ' +
                   'succeeds in changing the DNS servers there, every device in the house is ' +
                   'quietly redirected from then on.',
            title: 'No requests aimed at your router',
            failTitle: 'Page aims requests at your router',
            category: 'Network',
            needsDom: true,
            weight: 14,
            run: function (c) {
                var haystack = (c.html + ' ' + c.inline).toLowerCase();
                var gateways = GATEWAY_IPS.filter(function (ip) { return haystack.indexOf(ip) !== -1; });
                var paths = ROUTER_PATHS.filter(function (path) { return haystack.indexOf(path) !== -1; });
                if (!gateways.length && !paths.length) { return null; }
                if (isPrivateHost(c.host)) { return null; }     // you are on the router's own page
                var evidence = gateways.concat(paths).slice(0, 3).join(', ');
                return {
                    detail: 'The page references router administration addresses (' + evidence +
                            '), the shape of an attack that rewrites your network\'s DNS settings.',
                    points: gateways.length && paths.length ? 14 : 9
                };
            }
        },
        {
            id: 'dns-change-instructions',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page is talking you through changing DNS servers or signing into your ' +
                   'router. Whoever answers your DNS queries decides which machine every name in ' +
                   'your browser resolves to, so handing that over means every site you visit ' +
                   'afterwards can be replaced without a single warning.',
            title: 'No instructions to change your DNS or router',
            failTitle: 'Page talks you through changing DNS settings',
            category: 'Network',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), DNS_CHANGE_PHRASES);
                return hits.length
                    ? 'The page instructs you to change network settings: "' + hits.slice(0, 2).join('", "') + '".'
                    : null;
            }
        },
        {
            id: 'redirect-chain',
            about: 'You did not arrive here directly - the browser was passed along a chain of ' +
                   'addresses first. One hop is ordinary; several is how a campaign keeps its ' +
                   'landing page alive, sending each visitor through disposable links so the one ' +
                   'that gets reported is never the one that matters.',
            title: 'Reached without a redirect chain',
            failTitle: 'Reached through a chain of redirects',
            category: 'Network',
            needsDom: true,
            weight: 6,
            run: function (c) {
                var view = c.doc.defaultView;
                if (!view || !view.performance || !view.performance.getEntriesByType) { return null; }
                var nav = view.performance.getEntriesByType('navigation')[0];
                if (!nav || typeof nav.redirectCount !== 'number' || nav.redirectCount < 2) { return null; }
                return nav.redirectCount + ' redirects happened before this page was reached.';
            }
        },
        {
            id: 'downgraded-form',
            about: 'The page is encrypted but the form is not: what you type would be sent back ' +
                   'over a plain connection. The padlock you can see refers only to the page that ' +
                   'was delivered, so a form aimed at an unencrypted address undoes the protection ' +
                   'without changing anything you would notice.',
            cap: 35,
            title: 'Forms keep the encrypted connection',
            failTitle: 'Form drops out of the encrypted connection',
            category: 'Forms',
            needsDom: true,
            weight: 14,
            run: function (c) {
                if (c.url.protocol !== 'https:') { return null; }
                var bad = [];
                Array.prototype.forEach.call(c.doc.querySelectorAll('form[action]'), function (form) {
                    var target = resolveUrl(form.getAttribute('action'), c.href);
                    if (target && target.protocol === 'http:' && bad.length < 3) { bad.push(target.host); }
                });
                return bad.length
                    ? 'The padlock covers the page, not the form: it posts over plain HTTP to ' + bad.join(', ') + '.'
                    : null;
            }
        },
        {
            id: 'form-to-ip',
            about: 'The form sends what you type to a bare IP address. Legitimate sites post back ' +
                   'to a named host that belongs to them and can be traced to an owner; a numeric ' +
                   'collector belongs to whoever rented the machine this week and answers to no ' +
                   'name at all.',
            cap: 30,
            title: 'Forms post to a named host',
            failTitle: 'Form posts to a bare IP address',
            category: 'Forms',
            needsDom: true,
            weight: 14,
            run: function (c) {
                var bad = [];
                Array.prototype.forEach.call(c.doc.querySelectorAll('form[action]'), function (form) {
                    var target = resolveUrl(form.getAttribute('action'), c.href);
                    if (target && isIpHost(target.hostname) && bad.length < 3) { bad.push(target.hostname); }
                });
                return bad.length
                    ? 'A form posts your data to the raw address ' + bad.join(', ') + '.'
                    : null;
            }
        },
        {
            id: 'mailto-form',
            about: 'The form e-mails its contents instead of submitting them to a server. It is ' +
                   'the laziest possible collector and needs no hosting of its own, which is why ' +
                   'so many ready-made credential pages ship this way. No real sign-in page has ' +
                   'ever worked like this.',
            cap: 20,
            title: 'Forms do not e-mail your details away',
            failTitle: 'Form e-mails your details straight to someone',
            category: 'Forms',
            needsDom: true,
            weight: 16,
            run: function (c) {
                var found = null;
                Array.prototype.forEach.call(c.doc.querySelectorAll('form[action]'), function (form) {
                    var action = (form.getAttribute('action') || '').trim();
                    if (!found && /^mailto:/i.test(action)) { found = action.slice(7).split('?')[0]; }
                });
                return found
                    ? 'The form sends everything you type to ' + short(found, 40) + ' by e-mail.'
                    : null;
            }
        },

        /* --------------------- credential harvesting behaviour (62 - 72) */
        {
            id: 'credential-exfil',
            about: 'The page\'s own scripts carry an address that collects data - a chat bot, a ' +
                   'webhook, a form relay. Those endpoints need no server and no domain of the ' +
                   'attacker\'s own, which is exactly why phishing kits use them, and why an ' +
                   'ordinary login page never does.',
            cap: 8,
            title: 'No data-collection endpoint in the page scripts',
            failTitle: 'Page scripts post your data to a collector',
            category: 'Scripts',
            needsDom: true,
            weight: 20,
            run: function (c) {
                var found = INTEL.exfilEndpoints(c.inline + '\n' + c.html.slice(0, 120000));
                if (!found.length) { return null; }
                var high = found.some(function (item) { return item.severity === 'high'; });
                return {
                    detail: 'The page sends data to ' + found.map(function (f) { return f.name; }).join(', ') +
                            ' - an anonymous collector, not a service of this site.',
                    points: high ? 20 : 12,
                    cap: high ? 8 : 30
                };
            }
        },
        {
            id: 'credential-brand-mismatch',
            about: 'The page asks for a password while presenting itself as a company that does ' +
                   'not own this domain - in its title, its logo, or the copyright line it forgot ' +
                   'to change. A company\'s real sign-in page is always served from that company\'s ' +
                   'own domain, so the two can never honestly disagree.',
            cap: 12,
            title: 'Sign-in page matches the company that owns the domain',
            failTitle: 'Sign-in page wears another company\'s identity',
            category: 'Forms',
            needsDom: true,
            weight: 20,
            run: function (c) {
                if (!c.hasPassword) { return null; }
                if (!c.claims.length) { return null; }
                var brand = c.claims[0];
                return {
                    detail: 'The page presents itself as ' + brand + ' and asks for a password, but it is ' +
                            'served from ' + (c.domain || c.host) + ', not ' + (BRAND_SITES[brand] || brand) + '.',
                    points: 20,
                    cap: 12
                };
            }
        },
        {
            id: 'otp-harvest',
            about: 'The page wants a one-time code as well as a password. A code is only worth ' +
                   'stealing while it is valid, so a page collecting both is usually signing in as ' +
                   'you at that very moment and passing the challenge straight through - which is ' +
                   'how two-factor authentication gets defeated in practice.',
            title: 'No one-time code collected alongside a password',
            failTitle: 'Page collects a one-time code as well as a password',
            category: 'Forms',
            needsDom: true,
            weight: 12,
            run: function (c) {
                if (!c.hasPassword) { return null; }
                var fields = fieldsMatching(c.doc, ['otp', 'code', '2fa', 'token', 'mfa', 'pin']);
                var wording = countOccurrences(c.text.toLowerCase(), OTP_HINTS);
                if (!fields.length && wording.length < 2) { return null; }
                return 'The page asks for a password and a one-time code together (' +
                       (fields[0] || wording[0]) + '), the pattern of a live relay attack.';
            }
        },
        {
            id: 'seed-phrase-harvest',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page asks for a wallet\'s recovery phrase or private key. That phrase is ' +
                   'the wallet - anyone holding it can move everything in it, immediately and ' +
                   'irreversibly. No genuine wallet, exchange or support desk will ever ask you ' +
                   'to type it into a web page.',
            cap: 5,
            title: 'Does not ask for a wallet recovery phrase',
            failTitle: 'Page asks for your wallet recovery phrase',
            category: 'Forms',
            needsDom: true,
            weight: 22,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), SEED_PHRASE_WORDS);
                var fields = fieldsMatching(c.doc, ['seed', 'mnemonic', 'passphrase', 'privatekey', 'private_key', 'recovery']);
                if (!hits.length && !fields.length) { return null; }
                if (hits.length && !fields.length && !c.doc.querySelector('form, textarea, input')) {
                    return null;                      // an article explaining the scam, not running one
                }
                return {
                    detail: 'The page asks for "' + (hits[0] || fields[0]) + '". Whoever receives it owns the wallet outright.',
                    points: 22,
                    cap: 5
                };
            }
        },
        {
            id: 'wallet-drainer',
            about: 'The scripts connect a crypto wallet and then ask it to sign an approval rather ' +
                   'than a payment. An approval hands a contract standing permission to move your ' +
                   'tokens, so the transaction that empties the wallet happens later, long after ' +
                   'the page that arranged it has been closed.',
            cap: 10,
            title: 'No wallet-draining calls in the page scripts',
            failTitle: 'Page scripts ask your wallet to sign an approval',
            category: 'Scripts',
            needsDom: true,
            weight: 18,
            run: function (c) {
                var code = (c.inline + ' ' + c.html.slice(0, 120000)).toLowerCase();
                var hits = countOccurrences(code, DRAINER_METHODS);
                var connects = hits.indexOf('eth_requestaccounts') !== -1 || hits.indexOf('walletconnect') !== -1;
                var signs = hits.some(function (method) {
                    return ['personal_sign', 'eth_signtypeddata', 'eth_sign', 'setapprovalforall',
                            'increaseallowance', 'approve(', 'transferfrom(', 'signalltransactions',
                            'signandsendtransaction'].indexOf(method) !== -1;
                });
                if (!connects || !signs) { return null; }
                return {
                    detail: 'The page connects a wallet and requests ' +
                            hits.filter(function (h) { return h !== 'eth_requestaccounts'; }).slice(0, 3).join(', ') +
                            ' - permission to move your tokens, not a purchase.',
                    points: 18,
                    cap: 10
                };
            }
        },
        {
            id: 'hidden-password-field',
            about: 'A password box is present but hidden from view. The browser\'s saved-password ' +
                   'feature fills in fields it can find, whether or not you can see them, so an ' +
                   'invisible one on a page that appears to ask for nothing is there to collect ' +
                   'what your password manager offers.',
            title: 'No hidden password fields',
            failTitle: 'Page hides a password field',
            category: 'Forms',
            needsDom: true,
            weight: 7,
            run: function (c) {
                /* Only deliberate hiding counts. A box with no size is usually
                   a sign-in panel that has not been opened yet, or a page the
                   browser has not laid out - neither is an attack, and both
                   are far more common than one. */
                var hidden = 0;
                var visible = 0;
                Array.prototype.forEach.call(c.doc.querySelectorAll('input[type="password"]'), function (input) {
                    var style = elementStyle(c.doc, input);
                    if (!style) { visible++; return; }
                    var offscreen = (parseFloat(style.left) < -999) || (parseFloat(style.textIndent) < -999);
                    if (style.display === 'none' || style.visibility === 'hidden' ||
                        Number(style.opacity) === 0 || offscreen) {
                        // A panel waiting to be opened is hidden the same way.
                        var inPanel = input.closest && input.closest('dialog, [role="dialog"], [aria-modal], ' +
                            '[hidden], [class*="modal"], [class*="drawer"], [class*="popup"], [class*="menu"]');
                        if (!inPanel) { hidden++; }
                    } else {
                        visible++;
                    }
                });
                // A page that openly asks for a password is not hiding one.
                return (hidden && !visible)
                    ? hidden + ' password field(s) are deliberately hidden on a page that does not ask for one, ' +
                      'which is how a saved password gets collected by autofill.'
                    : null;
            }
        },
        {
            id: 'id-document-upload',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page wants a photograph of an identity document, or a selfie holding one. ' +
                   'That is the raw material for opening accounts in your name, and unlike a ' +
                   'password it can never be changed once it has been handed over. Very few sites ' +
                   'have any business asking.',
            title: 'Does not ask for identity documents',
            failTitle: 'Page asks you to upload identity documents',
            category: 'Forms',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var wording = countOccurrences(c.text.toLowerCase(), ID_DOCUMENT_WORDS);
                if (!wording.length) { return null; }
                var upload = c.doc.querySelector('input[type="file"]');
                if (!upload) { return null; }
                return 'The page asks you to upload "' + wording[0] + '", which is enough to open accounts in your name.';
            }
        },
        {
            id: 'keystroke-capture',
            about: 'The scripts watch individual keystrokes and send them onward. A form that ' +
                   'submits normally has no reason to read the keys one at a time, and a page that ' +
                   'does can collect what you typed even if you think better of it and never press ' +
                   'the button.',
            title: 'No keystroke logging in the page scripts',
            failTitle: 'Page scripts record what you type',
            category: 'Scripts',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var code = c.inline.toLowerCase();
                var listens = /addeventlistener\s*\(\s*['"](keydown|keypress|keyup|input)['"]/.test(code) ||
                              /onkeypress\s*=|onkeydown\s*=/.test(code);
                var sends = /(fetch\s*\(|xmlhttprequest|navigator\.sendbeacon|new image\(\)\.src|websocket\s*\()/.test(code);
                var reads = /\.value|password|input\.value/.test(code);
                if (!(listens && sends && reads)) { return null; }
                return 'Inline scripts listen to every keystroke and send data onward before the form is submitted.';
            }
        },
        {
            id: 'login-form-no-action',
            about: 'The sign-in form has nowhere to submit to, so the page is handling your ' +
                   'password in script instead. Real sign-in pages post to their own server; a form ' +
                   'with no destination is the shape left behind when a kit takes the values ' +
                   'itself and sends them somewhere of its choosing.',
            title: 'Sign-in form submits to a real destination',
            failTitle: 'Sign-in form has no real destination',
            category: 'Forms',
            needsDom: true,
            weight: 8,
            run: function (c) {
                if (!c.hasPassword) { return null; }
                var suspicious = false;
                Array.prototype.forEach.call(c.doc.querySelectorAll('form'), function (form) {
                    if (!form.querySelector('input[type="password"]')) { return; }
                    var action = (form.getAttribute('action') || '').trim();
                    if (action === '' || action === '#' || /^javascript:/i.test(action)) { suspicious = true; }
                });
                return suspicious
                    ? 'The sign-in form has no destination of its own, so a script decides where your password goes.'
                    : null;
            }
        },
        {
            id: 'srcdoc-credential-frame',
            about: 'A password box is being drawn inside a frame whose contents are written into ' +
                   'the page itself. Building the form that way keeps it out of the page source ' +
                   'that a scanner reads, and out of the address bar the frame would otherwise ' +
                   'have to show.',
            title: 'No password fields inside a written-in frame',
            failTitle: 'Password field hidden inside a written-in frame',
            category: 'Forms',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var found = false;
                Array.prototype.forEach.call(c.doc.querySelectorAll('iframe[srcdoc]'), function (frame) {
                    var markup = (frame.getAttribute('srcdoc') || '').toLowerCase();
                    if (markup.indexOf('type="password"') !== -1 || markup.indexOf("type='password'") !== -1) {
                        found = true;
                    }
                });
                return found
                    ? 'A password field is written into an inline frame, which keeps it out of the page\'s own source.'
                    : null;
            }
        },
        {
            id: 'cloned-brand-assets',
            about: 'Most of the images and stylesheets come from another company\'s servers. A ' +
                   'copied page keeps its looks by linking straight back to the original\'s files ' +
                   'rather than copying them, so the branding is genuine while everything that ' +
                   'receives your typing is not.',
            cap: 25,
            title: 'Page serves its own images and styles',
            failTitle: 'Page borrows another company\'s images and styles',
            category: 'Content',
            needsDom: true,
            weight: 14,
            run: function (c) {
                var counts = {};
                pageRefs(c).forEach(function (url) {
                    var domain = registrableDomain(url.hostname);
                    if (!domain || sameSite(url.hostname, c.host)) { return; }
                    BRAND_DOMAINS.forEach(function (brandDomain) {
                        if (domain === brandDomain) { counts[brandDomain] = (counts[brandDomain] || 0) + 1; }
                    });
                });
                var worst = null;
                Object.keys(counts).forEach(function (domain) {
                    if (!worst || counts[domain] > counts[worst]) { worst = domain; }
                });
                if (!worst || counts[worst] < 3) { return null; }
                return {
                    detail: counts[worst] + ' images or scripts are loaded from ' + worst +
                            ' while you are on ' + c.domain + ' - the signature of a copied page.',
                    points: clamp(6 + counts[worst] * 2, 6, 14)
                };
            }
        },

        /* ----------------------------- deception in the interface (73 - 82) */
        {
            id: 'fake-address-bar',
            about: 'The page draws its own address bar or padlock inside the page. Whatever is ' +
                   'painted there is just a picture, and it can spell any address at all - the ' +
                   'only address that means anything is the one in the browser\'s own frame, ' +
                   'above the page and outside its reach.',
            cap: 30,
            title: 'No fake address bar drawn on the page',
            failTitle: 'Page draws a fake address bar',
            category: 'Content',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var found = null;
                var candidates = c.doc.querySelectorAll('[class*="url"], [class*="addressbar"], [class*="address-bar"], [id*="urlbar"], [class*="browser"]');
                Array.prototype.forEach.call(candidates, function (node) {
                    if (found) { return; }
                    var text = (node.textContent || '').trim();
                    if (text.length > 120) { return; }
                    var match = text.match(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i);
                    if (match && !sameSite(match[1], c.host)) { found = match[1]; }
                });
                return found
                    ? 'The page paints an address bar showing "' + found + '" while you are on ' + c.host + '.'
                    : null;
            }
        },
        {
            id: 'fake-security-seal',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page shows a security badge that is not served by the company it names. A ' +
                   'genuine seal is an image fetched from the auditor, and clicking it proves the ' +
                   'audit; a copied picture proves only that somebody saved a picture and put it ' +
                   'next to the payment form.',
            title: 'No unverifiable security badges',
            failTitle: 'Page shows an unverifiable security badge',
            category: 'Content',
            needsDom: true,
            weight: 7,
            run: function (c) {
                var claims = countOccurrences(c.text.toLowerCase() + ' ' + c.html.slice(0, 60000).toLowerCase(), SECURITY_SEALS);
                if (!claims.length) { return null; }
                var verified = pageRefs(c).some(function (url) {
                    return SEAL_DOMAINS.indexOf(registrableDomain(url.hostname)) !== -1;
                });
                return verified
                    ? null
                    : 'The page claims "' + claims[0] + '" but the badge is not served by the company that would issue it.';
            }
        },
        {
            id: 'clickfix-clipboard',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page is walking you through running a command on your own computer, ' +
                   'usually after a fake verification step, and often after quietly putting that ' +
                   'command on your clipboard. It works because nothing is downloaded: you become ' +
                   'the delivery mechanism, and every browser warning is bypassed.',
            cap: 8,
            title: 'Does not ask you to run commands yourself',
            failTitle: 'Page talks you into running a command yourself',
            category: 'Scripts',
            needsDom: true,
            weight: 20,
            run: function (c) {
                var text = c.text.toLowerCase();
                var phrases = countOccurrences(text, CLICKFIX_PHRASES);
                var clipboard = countOccurrences(c.inline.toLowerCase(), CLIPBOARD_CALLS);
                var runners = /(powershell|cmd\.exe|mshta|curl\s+http|iwr\s+http|wscript|osascript|bash\s+-c)/i.test(text + ' ' + c.inline);
                var score = phrases.length + (clipboard.length ? 2 : 0) + (runners ? 2 : 0);
                if (score < 3) { return null; }
                return {
                    detail: 'The page instructs you to run something yourself ("' + short(phrases[0] || 'copied command', 40) +
                            '")' + (clipboard.length ? ' and writes to your clipboard while doing it' : '') + '.',
                    points: clamp(10 + score * 2, 10, 20),
                    cap: score >= 5 ? 8 : 25
                };
            }
        },
        {
            id: 'fake-captcha',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page dresses a permission prompt up as a human-verification step. The ' +
                   '"Allow" you are being pointed at is the browser\'s notification prompt, not a ' +
                   'captcha, and agreeing to it hands over the right to push adverts and fake ' +
                   'alerts onto your desktop long after the page is gone.',
            title: 'No fake human-verification prompt',
            failTitle: 'Page fakes a human-verification prompt',
            category: 'Content',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), FAKE_CAPTCHA_PHRASES);
                if (!hits.length) { return null; }
                return 'The page says "' + hits[0] + '" - that is the notification prompt, not a captcha.';
            }
        },
        {
            id: 'fake-update-prompt',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page claims your browser, plugin or driver is out of date and offers the ' +
                   'update itself. Browsers update themselves and never ask a web page to help; ' +
                   'anything downloaded from a page that says otherwise is whatever the page ' +
                   'wanted you to run.',
            title: 'No fake update prompt',
            failTitle: 'Page pushes a fake software update',
            category: 'Content',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), FAKE_UPDATE_PHRASES);
                if (!hits.length) { return null; }
                var offers = /download|install|update now|get the update/i.test(c.text.slice(0, 8000));
                return {
                    detail: 'The page claims "' + hits[0] + '"' + (offers ? ' and offers the update itself' : '') +
                            '. Browsers update themselves and never ask a page to do it.',
                    points: offers ? 12 : 7
                };
            }
        },
        {
            id: 'tech-support-number',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'A support telephone number is displayed next to a warning about your computer. ' +
                   'That combination is the whole business model of the support scam: the warning ' +
                   'is fabricated, the number reaches the people who wrote it, and the call ends ' +
                   'with remote access to the machine.',
            title: 'No support number attached to an alarm',
            failTitle: 'Support number displayed next to a scare message',
            category: 'Content',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var text = c.text.toLowerCase();
                var alarm = countOccurrences(text, SCAREWARE_STRONG).length ||
                            countOccurrences(text, SCAREWARE_WEAK).length >= 2;
                if (!alarm) { return null; }
                var callWording = /call (?:us|now|toll|support|immediately|this number)|helpline|support number/i.test(c.text);
                var number = SUPPORT_NUMBER.test(c.text.replace(/\s+/g, ' '));
                if (!callWording || !number) { return null; }
                return 'A telephone number is displayed beside a warning about your device - the shape of a support scam.';
            }
        },
        {
            id: 'install-prompt',
            about: 'The page offers something that installs rather than something that opens - an ' +
                   'Android package, a configuration profile, a browser add-on from outside a ' +
                   'store. Each of those grants standing access to the device, which is a very ' +
                   'different decision from opening a document.',
            title: 'Does not offer a direct install package',
            failTitle: 'Page offers a direct install package',
            category: 'Content',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var found = null;
                pageRefs(c).forEach(function (url) {
                    if (found) { return; }
                    var path = url.pathname.toLowerCase();
                    INSTALL_EXT.forEach(function (ext) {
                        if (!found && path.slice(-ext.length) === ext) { found = ext + ' from ' + url.host; }
                    });
                });
                return found
                    ? 'The page offers an install package (' + found + ') outside any app store.'
                    : null;
            }
        },
        {
            id: 'gift-card-payment',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page wants payment as gift card codes. No business collects money that ' +
                   'way; a code read out or photographed is gone the moment it is spent, cannot be ' +
                   'traced to anybody, and cannot be reversed by the shop that sold it. It is the ' +
                   'single clearest sign of a scam in progress.',
            title: 'Does not ask for gift card codes',
            failTitle: 'Page asks for payment in gift card codes',
            category: 'Content',
            needsDom: true,
            weight: 12,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), GIFT_CARD_PHRASES);
                return hits.length
                    ? 'The page asks for payment as "' + hits[0] + '" - untraceable and irreversible by design.'
                    : null;
            }
        },
        {
            id: 'giveaway-doubling',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page promises to send back more than you send in. The money multiplying ' +
                   'itself is the offer, and it has never once been real; the wallet address ' +
                   'changes, the celebrity name changes, and the arithmetic that nobody could ' +
                   'afford to honour stays exactly the same.',
            cap: 25,
            title: 'No "send money, get more back" offer',
            failTitle: 'Page promises to send back more than you send',
            category: 'Content',
            needsDom: true,
            weight: 14,
            run: function (c) {
                var text = c.text.toLowerCase();
                var hits = countOccurrences(text, GIVEAWAY_PHRASES);
                var arithmetic = /send\s+[\d.]+\s*(btc|eth|bnb|sol|usdt)[^.]{0,40}(receive|get|back)\s+[\d.]+/i.test(c.text);
                if (!hits.length && !arithmetic) { return null; }
                return {
                    detail: 'The page offers to return more than you send in ("' +
                            short(hits[0] || 'send X, receive 2X', 40) + '"), which no giveaway has ever done.',
                    points: arithmetic ? 14 : 9
                };
            }
        },
        {
            id: 'investment-guarantee',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'Returns are described as guaranteed or fixed by the day. Investment returns ' +
                   'cannot be guaranteed - that is what makes them investments - so the promise is ' +
                   'not an optimistic forecast but the pitch itself, and the withdrawal that is ' +
                   'always available never quite completes.',
            title: 'No guaranteed-return promises',
            failTitle: 'Page promises guaranteed investment returns',
            category: 'Content',
            needsDom: true,
            weight: 9,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), INVESTMENT_PHRASES);
                return hits.length >= 2
                    ? 'The page promises "' + hits.slice(0, 2).join('", "') + '", which no honest investment can.'
                    : null;
            }
        },
        {
            id: 'survey-prize',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'The page says you have been chosen, won something, or need only finish a short ' +
                   'survey to collect it. The prize exists to keep you moving through the pages ' +
                   'that follow, which is where the personal details, the card number or the ' +
                   'subscription is actually collected.',
            title: 'No prize or lucky-visitor claim',
            failTitle: 'Page claims you have won something',
            category: 'Content',
            needsDom: true,
            weight: 8,
            run: function (c) {
                var hits = countOccurrences(c.text.toLowerCase(), SURVEY_PHRASES);
                return hits.length
                    ? 'The page tells you "' + hits[0] + '" - the opening move of a survey or prize scam.'
                    : null;
            }
        },
        {
            id: 'qr-payment',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'A QR code is shown next to payment or urgency wording. The code hides its ' +
                   'destination until the phone has already opened it, and moving from the ' +
                   'computer to a phone leaves behind whatever protection the computer had. ' +
                   'Printed codes on letters and posters are swapped the same way.',
            title: 'No QR code attached to a payment request',
            failTitle: 'QR code shown next to a payment request',
            category: 'Content',
            needsDom: true,
            weight: 8,
            run: function (c) {
                var markup = c.html.slice(0, 120000).toLowerCase();
                var hasQr = markup.indexOf('qrcode') !== -1 || markup.indexOf('qr-code') !== -1 ||
                            /alt="[^"]*qr[^"]*"/.test(markup);
                if (!hasQr) { return null; }
                var money = /(scan to pay|pay with|payment|invoice|transfer|deposit|verify your account)/i.test(c.text);
                return money
                    ? 'A QR code is presented alongside payment wording; the code hides where it actually leads.'
                    : null;
            }
        },
        {
            id: 'subscription-trap',
            contextual: true,     // wording only: skipped where the visitor writes the words
            about: 'A recurring charge is mentioned in wording the layout keeps out of the way - ' +
                   'small print under a button, a line far below the fold. The trial is the ' +
                   'advertised offer and the subscription is the actual one, which is why the two ' +
                   'are never given the same prominence.',
            title: 'Recurring charges are not buried in small print',
            failTitle: 'Recurring charge buried in small print',
            category: 'Content',
            needsDom: true,
            weight: 7,
            run: function (c) {
                var recurring = /(you will be charged|automatically renew|recurring (?:charge|billing|payment)|per (?:week|month) (?:after|thereafter)|cancel any time to avoid)/i;
                var found = null;
                Array.prototype.forEach.call(c.doc.querySelectorAll('p, span, small, div'), function (node) {
                    if (found || (node.textContent || '').length > 400) { return; }
                    if (!recurring.test(node.textContent || '')) { return; }
                    var style = elementStyle(c.doc, node);
                    var size = style ? parseFloat(style.fontSize) : 16;
                    if ((size && size <= 11) || node.tagName === 'SMALL') { found = short(node.textContent, 70); }
                });
                return found
                    ? 'A recurring charge is disclosed only in small print: "' + found + '".'
                    : null;
            }
        },

        /* ------------------------------- evasion and anti-analysis (83 - 88) */
        {
            id: 'devtools-blocking',
            about: 'The page tries to stop you looking at how it is built - the right-click menu, ' +
                   'the view-source shortcut, the developer tools. An ordinary site has nothing to ' +
                   'protect there, since everything it sent you is already on your computer; a ' +
                   'copied sign-in page has the original\'s markup to hide.',
            title: 'Does not block inspection of the page',
            failTitle: 'Page blocks inspection of itself',
            category: 'Scripts',
            needsDom: true,
            weight: 9,
            run: function (c) {
                var code = c.inline.toLowerCase().replace(/\s+/g, '');
                var hits = DEVTOOLS_TOKENS.filter(function (token) {
                    return code.indexOf(token.replace(/\s+/g, '')) !== -1;
                });
                var blocks = /preventdefault/.test(code) || /returnfalse/.test(code);
                if (hits.length < 2 || !blocks) { return null; }
                return 'The page suppresses right-click, view-source or developer tools (' + hits.slice(0, 3).join(', ') + ').';
            }
        },
        {
            id: 'bot-cloaking',
            about: 'The scripts check whether the visitor is a person or an automated scanner and ' +
                   'can serve different content to each. Showing something harmless to whoever ' +
                   'checks the page, and the real thing to everybody else, is how a campaign stays ' +
                   'off the block lists for as long as possible.',
            title: 'No visitor cloaking in the page scripts',
            failTitle: 'Page checks whether you are a real visitor',
            category: 'Scripts',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var code = c.inline.toLowerCase();
                var hits = countOccurrences(code, CLOAKING_TOKENS);
                if (!hits.length) { return null; }
                var branches = /if\s*\(|\?\s*.+:/.test(code) && /(location\.(replace|href)|innerhtml|document\.write)/.test(code);
                if (!branches) { return null; }
                return 'The page inspects the visitor (' + hits.slice(0, 2).join(', ') +
                       ') and changes what it shows accordingly.';
            }
        },
        {
            id: 'dynamic-script-injection',
            about: 'Code is being assembled at run time and added to the page, often from text ' +
                   'that was encoded to be unreadable in the source. Whatever finally runs is ' +
                   'decided after the page has loaded, so nothing you or a scanner reads in the ' +
                   'markup describes what the page actually does.',
            title: 'No scripts assembled at run time',
            failTitle: 'Page assembles its scripts at run time',
            category: 'Scripts',
            needsDom: true,
            weight: 8,
            run: function (c) {
                var code = c.inline.toLowerCase().replace(/\s+/g, '');
                var creates = /createelement\(['"]script['"]\)/.test(code) || /insertadjacenthtml\(/.test(code);
                var hidden = /atob\(|fromcharcode|unescape\(|\\x6|decodeuricomponent\(/.test(code);
                if (!creates || !hidden) { return null; }
                return 'A script element is built at run time from encoded text, so its real source is not in the page.';
            }
        },
        {
            id: 'history-trap',
            about: 'The page fills the browser history with copies of itself so that pressing back ' +
                   'never gets you anywhere. Holding a visitor on the page is the point: the ' +
                   'longer the fake warning or the countdown stays in front of somebody, the more ' +
                   'likely they are to do what it asks.',
            title: 'Back button works normally',
            failTitle: 'Page traps the back button',
            category: 'Scripts',
            needsDom: true,
            weight: 7,
            run: function (c) {
                var code = c.inline.toLowerCase().replace(/\s+/g, '');
                var pushes = (code.match(/history\.(pushstate|replacestate)/g) || []).length;
                var loops = /setinterval|for\(|while\(|popstate/.test(code);
                if (pushes < 1 || !loops) { return null; }
                return 'The page rewrites the browser history repeatedly, which stops the back button leaving.';
            }
        },
        {
            id: 'data-uri-navigation',
            about: 'The page links to a whole document encoded inside the link itself, or to code ' +
                   'in place of an address. What opens is written by this page rather than fetched ' +
                   'from anywhere, so it inherits the trust of the site you are on while nobody ' +
                   'else ever hosted or checked it.',
            title: 'No links to inline documents or script',
            failTitle: 'Page links to inline documents or script',
            category: 'Content',
            needsDom: true,
            weight: 10,
            run: function (c) {
                var found = null;
                Array.prototype.forEach.call(c.doc.querySelectorAll('a[href], iframe[src]'), function (node) {
                    if (found) { return; }
                    var raw = (node.getAttribute('href') || node.getAttribute('src') || '').trim().toLowerCase();
                    if (/^data:text\/html/.test(raw)) { found = 'a document encoded into the link'; }
                    else if (/^javascript:/.test(raw) && raw.length > 30) { found = 'script in place of an address'; }
                });
                return found ? 'The page contains ' + found + ', which never came from a server.' : null;
            }
        }
    ];

    /* --------------------------------------------------- attack patterns */

    /*
     * Some findings mean little apart and a great deal together. A password
     * box is ordinary; a password box on a free sub-domain wearing a bank's
     * logo is a phishing kit, and no single test can say so. Each pattern
     * lists groups of findings and how many of those groups have to appear.
     */
    var PATTERNS = [
        {
            id: 'credential-kit',
            title: 'Credential harvesting kit',
            about: 'Three things showed up together: something collecting a password, a disposable ' +
                   'place to host it, and somebody else\'s identity on the page. Each is explainable ' +
                   'alone. Together they are the standard build of a phishing kit.',
            need: 2,
            points: 12,
            cap: 18,
            groups: [
                ['insecure-password-form', 'login-form-no-action', 'cross-domain-form', 'mailto-form',
                 'credential-exfil', 'otp-harvest', 'credential-brand-mismatch', 'form-to-ip',
                 'downgraded-form', 'srcdoc-credential-frame', 'hidden-password-field'],
                ['free-subdomain-host', 'dynamic-dns-host', 'suspicious-tld', 'ip-host', 'random-domain',
                 'kit-path', 'brand-in-domain', 'many-subdomains', 'tld-in-subdomain', 'shortener',
                 'homograph-brand', 'typosquat-brand', 'at-symbol'],
                ['brand-impersonation', 'title-brand-mismatch', 'credential-brand-mismatch',
                 'cloned-brand-assets', 'favicon-hotlink', 'fake-address-bar', 'brand-in-domain',
                 'homograph-brand', 'typosquat-brand']
            ]
        },
        {
            id: 'pharming',
            title: 'Pharming / redirected traffic',
            about: 'The page is either pointing your browser at machines inside a private network, ' +
                   'or working on the router that decides where every name you type resolves to. ' +
                   'That is how traffic gets quietly sent to somebody else\'s server while the ' +
                   'address bar still shows the name you asked for.',
            need: 2,
            points: 12,
            cap: 22,
            groups: [
                ['private-network-target', 'router-attack', 'dns-change-instructions', 'form-to-ip'],
                ['ip-host', 'https', 'downgraded-form', 'insecure-password-form', 'mixed-content',
                 'nonstandard-port', 'credential-brand-mismatch', 'title-brand-mismatch']
            ]
        },
        {
            id: 'crypto-drainer',
            title: 'Crypto wallet drainer',
            about: 'The page combines wallet machinery with somebody else\'s branding or a promise ' +
                   'of free money. Signing what a page like this asks for is not a payment, it is ' +
                   'permission, and it cannot be taken back afterwards.',
            need: 2,
            points: 14,
            cap: 12,
            groups: [
                ['seed-phrase-harvest', 'wallet-drainer', 'crypto-wallet'],
                ['brand-impersonation', 'brand-in-domain', 'giveaway-doubling', 'title-brand-mismatch',
                 'cloned-brand-assets', 'homograph-brand', 'typosquat-brand', 'investment-guarantee']
            ]
        },
        {
            id: 'support-scam',
            title: 'Fake support / scareware',
            about: 'An invented warning about your device, plus something engineered to keep you ' +
                   'on the page or on the telephone. No web page can examine your computer, so ' +
                   'the alarm is theatre and the number belongs to whoever wrote it.',
            need: 2,
            points: 10,
            cap: 22,
            groups: [
                ['scareware', 'tech-support-number', 'fake-update-prompt'],
                ['popup-traps', 'history-trap', 'permission-abuse', 'fake-captcha', 'auto-download',
                 'full-page-iframe', 'overlay-ads']
            ]
        },
        {
            id: 'malware-delivery',
            title: 'Malware delivery page',
            about: 'Something on this page installs or runs, and the page also takes trouble to ' +
                   'hide how it works. Those two together describe a delivery page rather than a ' +
                   'download you went looking for.',
            need: 2,
            points: 12,
            cap: 18,
            groups: [
                ['auto-download', 'executable-url', 'double-extension', 'install-prompt',
                 'archive-download', 'clickfix-clipboard'],
                ['obfuscated-js', 'dynamic-script-injection', 'bot-cloaking', 'devtools-blocking',
                 'fake-update-prompt', 'data-uri-navigation', 'hidden-iframes']
            ]
        },
        {
            id: 'prize-scam',
            title: 'Prize, giveaway or advance-fee scam',
            about: 'The page makes an offer nobody makes - a prize, guaranteed returns, money back ' +
                   'from money sent - and it is published somewhere disposable or gives no way to ' +
                   'reach whoever is behind it. The offer and the anonymity go together.',
            need: 2,
            points: 12,
            cap: 30,
            groups: [
                ['spam-phrases:high', 'survey-prize', 'giveaway-doubling', 'investment-guarantee',
                 'gift-card-payment', 'scareware:high'],
                ['suspicious-tld', 'free-subdomain-host', 'dynamic-dns-host', 'random-domain',
                 'contact-info', 'https', 'brand-in-domain', 'shortener', 'hidden-text']
            ]
        },
        {
            id: 'evasive-page',
            title: 'Page hiding how it works',
            about: 'Packed code, run-time assembly, visitor checks, blocked developer tools: each ' +
                   'has an innocent explanation on its own, and a page that does several at once ' +
                   'is being built to be difficult to examine.',
            need: 1,
            minInGroup: 3,
            points: 10,
            cap: 30,
            groups: [
                ['obfuscated-js', 'dynamic-script-injection', 'bot-cloaking', 'devtools-blocking',
                 'meta-refresh', 'hidden-iframes', 'encoded-chars', 'data-uri-navigation']
            ]
        }
    ];

    /**
     * @param {Array} failed  check ids, or the failed entries themselves.
     *   A group may write "spam-phrases:high" to mean that the finding has to
     *   be a serious one - three hard-sell phrases on a shop must not stand in
     *   for the vocabulary of an actual prize scam.
     */
    function matchPatterns(failed) {
        var points = {};
        (failed || []).forEach(function (item) {
            if (typeof item === 'string') { points[item] = 99; }
            else if (item && item.id) { points[item.id] = typeof item.points === 'number' ? item.points : 99; }
        });
        var present = function (token) {
            var parts = token.split(':');
            var scored = points[parts[0]];
            if (scored === undefined) { return false; }
            return parts[1] === 'high' ? scored >= 10 : true;
        };

        var found = [];
        PATTERNS.forEach(function (pattern) {
            var evidence = [];
            var groupsHit = 0;
            /* A finding may only answer for one group. Without that, a single
               look-alike domain would satisfy both "a disposable host" and
               "somebody else's identity" and invent a pattern out of one fact. */
            var spent = [];
            pattern.groups.forEach(function (group) {
                var hits = group.map(function (token) { return token.split(':')[0]; })
                    .filter(function (id, i) {
                        return present(group[i]) && spent.indexOf(id) === -1;
                    });
                if (hits.length >= (pattern.minInGroup || 1)) {
                    groupsHit++;
                    hits.forEach(function (id) { spent.push(id); });
                    hits.slice(0, 4).forEach(function (id) {
                        if (evidence.indexOf(id) === -1) { evidence.push(id); }
                    });
                }
            });
            if (groupsHit >= pattern.need) {
                var complete = groupsHit === pattern.groups.length && pattern.groups.length > 1;
                found.push({
                    id: pattern.id,
                    title: pattern.title,
                    about: pattern.about,
                    detail: 'Recognised from ' + evidence.length + ' findings: ' + evidence.join(', ') + '.',
                    evidence: evidence,
                    points: complete ? pattern.points + 4 : pattern.points,
                    cap: complete ? Math.max(5, pattern.cap - 6) : pattern.cap
                });
            }
        });
        return found;
    }

    /* -------------------------------------------------------------- rating */

    function ratingFor(score) {
        if (score >= 90) { return {grade: 'A', verdict: 'Safe', level: 'safe'}; }
        if (score >= 75) { return {grade: 'B', verdict: 'Probably safe', level: 'ok'}; }
        if (score >= 60) { return {grade: 'C', verdict: 'Use caution', level: 'caution'}; }
        if (score >= 40) { return {grade: 'D', verdict: 'Suspicious', level: 'risky'}; }
        return {grade: 'F', verdict: 'Likely spam / unsafe', level: 'danger'};
    }

    // What to call a page the reputation layer recognised outright.
    var THREAT_VERDICTS = {
        phishing: 'Known phishing page',
        malware: 'Known malware page',
        pua: 'Known unwanted-software page',
        blocked: 'Blocked address',
        test: 'Security feature test page'
    };

    function severityFor(points) {
        if (points >= 10) { return 'high'; }
        if (points >= 5) { return 'medium'; }
        return 'low';
    }

    /* ------------------------------------------------------------ analyse */

    /**
     * Analyse a page.
     * @param {Object|string} options  URL string, or {url, document, budgetMs}
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
                patterns: [],
                blocked: false,
                threat: null,
                context: {kind: null, userDriven: false, reason: ''},
                totalTests: 0,
                analysedAt: new Date().toISOString(),
                error: 'The address "' + href + '" could not be parsed.'
            };
        }

        var host = url.hostname.toLowerCase();
        var domain = registrableDomain(url.hostname);

        /* What kind of page this is decides how much of its text belongs to
           the site, so the question is settled before the text is read. */
        var context = pageContext(host, domain, doc);
        var authorship = doc ? splitAuthorship(doc, url, context.userDriven) : {site: '', user: ''};

        var ctx = {
            href: href,
            url: url,
            host: host,
            domain: domain,
            decodedHost: decodeHost(host),
            decodedDomain: registrableDomain(decodeHost(host)),
            doc: doc,
            /* text is what the SITE says. Anything the visitor typed, searched
               for, or was shown from somebody else has been taken out of it. */
            text: authorship.site,
            userText: authorship.user,
            html: doc ? pageMarkup(doc) : '',
            inline: doc ? inlineScriptSource(doc) : '',
            intel: INTEL.lookup(url),
            context: context
        };
        ctx.hasPassword = !!(doc && doc.querySelector('input[type="password"]'));
        ctx.claims = doc ? claimedBrands(ctx) : [];

        var results = [];
        var threatPoints = 0;
        var hygienePoints = 0;
        var rawPenalty = 0;
        var scoreCap = 100;
        var cappedBy = [];

        /* Page tests walk the DOM, so a huge or hostile page could make the
           scan feel like a freeze. Once the budget is spent the remaining page
           tests are skipped rather than run. */
        var budgetMs = typeof options.budgetMs === 'number' ? options.budgetMs : 2500;
        var deadline = Date.now() + budgetMs;

        CHECKS.forEach(function (check) {
            var hygiene = !!HYGIENE_CHECKS[check.id];
            var entry = {
                id: check.id,
                title: check.title,          // replaced by failTitle when the test fails
                about: check.about,          // plain-English explanation for the report
                category: check.category,
                weight: check.weight,
                impact: hygiene ? 'hygiene' : 'threat',
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

            /*
             * The wording tests ask "what is this page claiming?". On a page
             * where the words belong to whoever is using it - an assistant, a
             * search results list, an inbox - that question has no meaning,
             * so the test is skipped rather than answered wrongly.
             */
            if (check.contextual && ctx.context.userDriven) {
                entry.status = 'skipped';
                entry.detail = ctx.context.reason;
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
                rawPenalty += points;
                if (hygiene) { hygienePoints += points; } else { threatPoints += points; }
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

        var failed = results.filter(function (r) { return r.status === 'failed'; });
        var failedIds = failed.map(function (r) { return r.id; });

        /* Findings that only mean something in combination. */
        var patterns = matchPatterns(failed);
        var patternPoints = 0;
        patterns.forEach(function (pattern) {
            patternPoints += pattern.points;
            cappedBy.push(pattern.id);
            if (pattern.cap < scoreCap) { scoreCap = pattern.cap; }
        });

        /*
         * Normalising the score.
         *
         * The penalty is measured against a fixed points budget rather than
         * against the weight of the suite. Dividing by the suite would mean
         * that adding a test made every existing finding count for less, so
         * a scanner would get gentler the more it learned to look for.
         *
         * Nuisance findings - advertising, tracker sprawl, no contact page -
         * share a small budget of their own. An ad-heavy newspaper should lose
         * a few points and stay in the safe band; only genuine risk should be
         * able to take a page out of it.
         */
        var reference = doc ? RISK_POINTS_PAGE : RISK_POINTS_URL;
        var penalty = threatPoints + Math.min(hygienePoints, HYGIENE_BUDGET) + patternPoints;
        var riskRatio = penalty / reference;
        var score = clamp(Math.round(100 - riskRatio * 100), 0, 100);

        /*
         * Some findings are close to conclusive on their own - an address on
         * the known-threat list, a domain one character away from paypal.com,
         * a page asking for a wallet's recovery phrase. Averaging those
         * against ninety tests that passed would hide them, so they also cap
         * the final score.
         */
        var uncapped = score;
        score = Math.min(score, scoreCap);

        var rating = ratingFor(score);
        var verdict = rating.verdict;
        var blocked = false;

        /* A reputation hit is not a matter of degree: it is a name we already
           know, and the report should say so rather than quote a number. */
        var identified = ctx.intel || (failedIds.indexOf('test-page-signature') !== -1
            ? INTEL.matchPageSignature(ctx.text + ' ' + (doc ? doc.title || '' : '')) : null);
        if (identified) {
            blocked = true;
            verdict = THREAT_VERDICTS[identified.kind] || 'Known threat';
        }

        var available = results.reduce(function (sum, r) {
            return r.status === 'skipped' ? sum : sum + r.weight;
        }, 0);

        return {
            url: href,
            host: ctx.host,
            domain: ctx.domain,
            score: score,
            penalty: penalty,
            rawPenalty: rawPenalty,
            threatPenalty: threatPoints,
            hygienePenalty: hygienePoints,
            patternPenalty: patternPoints,
            maxPenalty: available,
            riskBudget: reference,
            riskRatio: Math.round(riskRatio * 1000) / 1000,
            scoreCap: scoreCap,
            cappedBy: score < uncapped ? cappedBy : [],
            rating: rating.grade,
            verdict: verdict,
            level: rating.level,
            blocked: blocked,
            threat: identified ? {
                kind: identified.kind,
                label: identified.label,
                detail: identified.detail || '',
                source: identified.source
            } : null,
            context: {
                kind: ctx.context.kind,
                userDriven: ctx.context.userDriven,
                reason: ctx.context.reason
            },
            patterns: patterns,
            isSpam: score < 60,
            checks: results,
            failed: failed.sort(function (a, b) { return b.points - a.points; }),
            passed: results.filter(function (r) { return r.status === 'passed'; }),
            skipped: results.filter(function (r) { return r.status === 'skipped'; }),
            totalTests: results.length,
            intelVersion: INTEL.version,
            analysedAt: new Date().toISOString()
        };
    }

    return {
        analyze: analyze,
        analyse: analyze,               // British spelling alias
        ratingFor: ratingFor,
        registrableDomain: registrableDomain,
        decodeHost: decodeHost,
        latinSkeleton: latinSkeleton,
        pageContext: pageContext,
        splitAuthorship: splitAuthorship,
        matchPatterns: matchPatterns,
        addThreatEntries: function (list) { return INTEL.addEntries(list); },
        checks: CHECKS,
        patterns: PATTERNS,
        intel: INTEL,
        version: '2.0.0'
    };
}));
