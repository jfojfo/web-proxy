# web-proxy

> A node web proxy

## create certificate file
```
$ openssl genrsa -out private.pem 2048
$ openssl req -new -x509 -key private.pem -out public.crt -days 99999
```

Common Name填写https代理服务器域名或IP

