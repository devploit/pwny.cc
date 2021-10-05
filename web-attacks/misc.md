# Misc

## Manual Requests

### Netcat

```bash
#Netcat scanner for HTTP servers
for i in $(seq 1 255); do nc -n -v -z "192.168.1.$i" 80 | grep "open"; done | tee webservers.txt

#Manually perform a HTTP Get Request
echo -ne "GET / HTTP/1.0\n\n" | nc www.web.com 80
```

### Socat

```bash
#Manually perform a HTTP Get Request on SSL port
echo -ne "GET / HTTP/1.0\n\n" | socat – OPENSSL:www.web.com:443,verify=0

#Check if TRACE is enabled on website
echo -ne "TRACE /something HTTP/1.0\nX-Header: Trace Enabled\n\n" | socat - OPENSSL:www.web.com:443,verify=0
```

