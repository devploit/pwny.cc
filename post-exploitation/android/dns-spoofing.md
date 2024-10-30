# dns spoofing

## dnsmasq

### Setup dnsmasq

dnsmasq.conf

```
address=/appserver.com/192.168.178.37
address=/otherserver.com/192.168.178.37
log-queries
```

Run dnsmasq using docker

{% code overflow="wrap" %}
```bash
docker pull andyshinn/dnsmasq
docker run --name my-dnsmasq --rm -it -p 0.0.0.0:53:53/udp \
 -v D:\tmp\proxy\dnsmasq.conf:/etc/dnsmasq.conf andyshinn/dnsmasq.conf andyshinn/dnsmasq
```
{% endcode %}

## Configure DNS server on Android

### Option 1:  Settings way

Change DNS configuration from settings apps (but unfortunately some apps like Chrome will ignore our DNS server)

### Option 2: DNS over VPN

Using [rethinkdns app](https://github.com/celzero/rethink-app) we can control this:

1. Change DNS settings to "Other DNS"
2. Selext "Proxy DNS" (DNS 53)
3. Create a new entry pointing ot your local DNS server host
4. Launch the VPN

You can check whether DNS spoofing works by going to Google Chrome and visit `chrome://net-internals`.
