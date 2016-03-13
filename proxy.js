var http = require('http');
var https = require('https');
var fs = require('fs');
var net = require('net');
var url = require('url');

var HTTPS_PORT = 55443;
var HTTP_PORT = 55080;

function unauthorized(res, realm) {
  // res.statusCode = 401;
  // res.setHeader('WWW-Authenticate', 'Basic realm="' + realm + '"');
  res.statusCode = 407;
  res.setHeader('Proxy-Authenticate', 'Basic realm="' + realm + '"');
  res.setHeader('Connection', 'close');
  res.end('Unauthorized');
}

function checkAuth(req) {
    if (req.user) {
        return true;
    }
    // var authorization = req.headers.authorization;
    var authorization = req.headers['proxy-authorization'];
    if (authorization) {
        var parts = authorization.split(' ');
        if (parts.length === 2) {
            var scheme = parts[0];
            var credentials = new Buffer(parts[1], 'base64').toString();
            var index = credentials.indexOf(':');
            var user = credentials.slice(0, index);
            var pass = credentials.slice(index + 1);

            if (user === 'doudou' && pass === 'welovedoudou') {
                req.user = req.remoteUser = user;
                return true;
            } else {
                console.log("invalid user/password: " + user + ", " + pass);
            }
        }
    }
    return false;
}

function log(req, res) {
    var statusCode = res ? res.statusCode : '';
    console.log('[' + new Date().toLocaleString() + ']',
        '"' + req.method + ' ' + req.url + ' http/' + req.httpVersion + '"',
        statusCode, '-',
        '"' + req.headers['user-agent'] + '"' || '');
}

function request(cReq, cRes) {
    if (!checkAuth(cReq)) {
        unauthorized(cRes, 'Authorization Required');
        return;
    }

    var u = url.parse(cReq.url);
    var options = {
        hostname : u.hostname, 
        port     : u.port || 80,
        path     : u.path,       
        method     : cReq.method,
        headers     : cReq.headers
    };

    var pReq = http.request(options, function(pRes) {
        log(cReq, pRes);
        cRes.writeHead(pRes.statusCode, pRes.headers);
        pRes.pipe(cRes);
    }).on('error', function(e) {
        cRes.end();
    });

    cReq.pipe(pReq);
}

function connect(cReq, cSock) {
    if (!checkAuth(cReq)) {
        cSock.write('HTTP/1.1 407 Proxy Authorization\r\nProxy-Authenticate: Basic realm="Authorization Required"\r\nConnection: close\r\n\r\n');
        cSock.end();
        return;
    }

    var u = url.parse('http://' + cReq.url);

    var pSock = net.connect(u.port, u.hostname, function() {
        log(cReq);
        cSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        pSock.pipe(cSock);
    }).on('error', function(e) {
        cSock.end();
    });

    cSock.pipe(pSock);
}

var options = {
    key: fs.readFileSync('./private.pem'),
    cert: fs.readFileSync('./public.crt')
};

https.createServer(options)
    .on('request', request)
    .on('connect', connect)
    .listen(HTTPS_PORT, '0.0.0.0');

http.createServer()
    .on('request', request)
    .on('connect', connect)
    .listen(HTTP_PORT, '0.0.0.0');

console.log('Listening at 0.0.0.0:' + HTTPS_PORT);
console.log('Listening at 0.0.0.0:' + HTTP_PORT);

