var http = require('http');
var https = require('https');
var fs = require('fs');
var net = require('net');
var url = require('url');

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
            }
        }
    }
    return false;
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
        console.log('request...');
        cRes.writeHead(pRes.statusCode, pRes.headers);
        pRes.pipe(cRes);
    }).on('error', function(e) {
        cRes.end();
    });

    cReq.pipe(pReq);
}

function connect(cReq, cSock) {
    console.log(cReq.headers)
    if (!checkAuth(cReq)) {
        cSock.write('HTTP/1.1 407 Proxy Authorization\r\nProxy-Authenticate: Basic realm="Authorization Required"\r\nConnection: close\r\n\r\n');
        cSock.end();
        return;
    }

    var u = url.parse('http://' + cReq.url);

    var pSock = net.connect(u.port, u.hostname, function() {
        console.log('connect...');
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
// http.createServer()
    .on('request', request)
    .on('connect', connect)
    .listen(55443, '0.0.0.0');
