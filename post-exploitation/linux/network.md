# Network

### Socat TCP redirection

```bash
#Example HTTP redirection: socat TCP4-LISTEN:80,fork TCP4:10.10.10.19:80
socat TCP4-LISTEN:<PORT>,fork TCP4:<REMOTE-HOST-IP-ADDRESS>:<REMOTE-HOST-PORT>
```

### Chisel TCP tunnel over HTTP

```bash
#Download chisel for victim machine version
#10.10.10.19 == kali_IP. 4506 == Port to redirect.
./chisel client 10.10.10.19:10000 R:4506:127.0.0.1:4506 #In Victim Machine
./chisel server -p 10000 --reverse #In Kali Machine
```

{% embed url="https://github.com/jpillora/chisel/releases" %}
Chisel - Releases
{% endembed %}

### Enum ports using nc

```bash
#nc -zv IP PORT-RANGE
nc -zv 127.0.0.1 20-80
```

### Scan IP/Ports from Bash

```bash
for ip in {1..254};
do for port in {22,80,443};
	do (echo >/dev/tcp/10.10.10.$ip/$port) >& /dev/null \
	&& echo "10.10.10.$ip:$port is open";
	done;
done;
```
