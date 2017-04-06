# golang-socks-proxy
基于SOCKS5协议实现一个简单代理服务


## Features 
- [x] CONNECT cmd, proxy for tcp-based client
- [] BIND cmd
- [] UDP ASSOCIATE
- [] authencation 

## Build
* `go build socksproxy.go -o socksproxy`

## Run
* `./socksproxy -bind :1088`
