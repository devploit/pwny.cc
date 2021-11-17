# John the Ripper

### Tool

{% embed url="https://github.com/openwall/john" %}
John the Ripper Jumbo - Advanced Offline Password Cracker
{% endembed %}

### Use of FILE2john

There are several scripts to convert any software format to john (keepass2john.py, zip2john.py, cisco2john.pl) located on john/run path. We use these scripts to create hash files that we can crack later with JTR.

```bash
#Example
python zip2john.py encrypted.zip > zip.hash
```

### John parameters

```
-f=[format] / --format=[format]
-w=[wordlist path] / --wordlist=[wordlist path]
```

### Attack examples

```bash
#Attack to md5 hash file
john -f=raw-md5 -w=/usr/share/wordlists/rockyou.txt md5.hash

#Attack to sha1 hash file
john -f=raw-sha1 -w=/usr/share/wordlists/rockyou.txt md5.hash
```
