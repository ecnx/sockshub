Purpose
-------
Connect Tor then SOCKS-5 Proxy
SOCKS-5 Authenticator
Redirect SOCKS-5 Traffic by Hostname Filter

Building
--------
```
make
```

Example
-------
* Connect SOCKS-5 Proxy behind Tor
```
sockshub -v -g 127.0.0.1:9050 -l [::1]:7070 -p [proxy-ipv6]:proxy-port
```

* Stick user:pass to SOCKS-5 client
```
sockshub -v -l [::1]:7070 -p proxy-ipv4:proxy-port -c MyUserName:MySecretPassword
```

* Connect example.com via 1st proxy, example.org via 2nd proxy
```
sockshub -v -l [::1]:7070 -p proxy-1st-ipv4:proxy-1st-port -f ',example.com,' -s proxy-2nd-ipv4:proxy-2nd-port
```

* Connect SOCKS-5 Proxy behind Tor, but connect with Tor behind VPS
```
sockshub -v -g vps-ipv4:vps-port -b 127.0.0.1:9050 -l [::1]:7070 -p proxy-ipv4:proxy-port
```

* Check the connection
```
curl -x socks5h://[::1]:7070 http://<ip-check-website> -o -
```

Help message
------------

```
[shub] SocksHub - ver. 1.05.1a
[shub] usage: sockshub option [value]...

       -v                Enable verbose logging
       -d                Run in background
       -g addr:port      Connect via gateway
       -b addr:port      Bridge for primary server
       -l addr:port      Listen for incoming data
       -p addr:port      Primary socks5 server
       -c user:pass      Primary socks5 credentials
       -f filter          Primary hostname filter
       -s addr:port      Secondary socks5 server
       -q addr:port      Secondary socks5 credentials

Note: Both IPv4 and IPv6 can be used

```
