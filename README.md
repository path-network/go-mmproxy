# go-mmproxy

This is a Go reimplementation of [mmproxy](https://github.com/cloudflare/mmproxy), created to improve on mmproxy's runtime stability while providing potentially greater performance in terms of connection and packet throughput.

`go-mmproxy` is a standalone application that unwraps HAProxy's [PROXY protocol](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) (also adopted by other projects such as NGINX) so that the TCP connection to the end server comes from client's - instead of proxy server's - IP address and port number.
Because they share basic mechanisms, [Cloudflare's blogpost on mmproxy](https://blog.cloudflare.com/mmproxy-creative-way-of-preserving-client-ips-in-spectrum/) serves as a great write-up on how `go-mmproxy` works under the hood.

## Building

```shell
go get github.com/path-network/go-mmproxy
```

You'll need at least `go 1.11` to build the `go-mmproxy` binary.
See [Go's Getting Started](https://golang.org/doc/install) if your package manager does not carry new enough version of golang.

## Requirements

`go-mmproxy` has to be ran:

- on the same server as the proxy target, as the communication happens over the loopback interface;
- as root or with `CAP_NET_ADMIN` capability to be able to set `IP_TRANSPARENT` socket opt.

## Running

### Routing setup

Route all traffic originating from loopback back to loopback:

```shell
ip rule add from 127.0.0.1/8 iif lo table 123
ip route add local 0.0.0.0/0 dev lo table 123

ip -6 rule add from ::1/128 iif lo table 123
ip -6 route add local ::/0 dev lo table 123
```

If `--mark` option is given to `go-mmproxy`, all packets routed to the loopback interface will have the mark set.
This can be used for setting up more advanced routing rules with iptables, for example when you need traffic from loopback to be routed outside of the machine.

### Starting go-mmproxy

```
Usage of ./go-mmproxy:
  -4 string
    	Address to which IPv4 TCP traffic will be forwarded to (default "127.0.0.1:443")
  -6 string
    	Address to which IPv6 TCP traffic will be forwarded to (default "[::1]:443")
  -allowed-subnets string
    	Path to a file that contains allowed subnets of the proxy servers
  -l string
    	Adress the proxy listens on (default "0.0.0.0:8443")
  -listeners int
    	Number of listener sockets that will be opened for the listen address (default 1)
  -mark int
    	The mark that will be set on outbound packets
  -v int
    	0 - no logging of individual connections
    	1 - log errors occuring in individual connections
    	2 - log all state changes of individual connections


```

Example invocation:

```shell
sudo ./go-mmproxy -l 0.0.0.0:25577 -4 127.0.0.1:25578 -6 [::1]:25578 --allow-subnets ./path-prefixes.txt
```
