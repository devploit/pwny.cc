# Internal Recon

### Sudo - Useful Commands

```bash
#List user's privileges
sudo -l
```

### Find - Useful Commands \#SUID \#SGID \#StickyBit

```bash
#Find world writeable directories
find / -perm 777 2>/dev/null

#Find SUID files
find / -perm /4000 -type f 2>/dev/null

#Find root SUID files
find / -perm /4000 -uid 0 -type f 2>/dev/null

#Find SGID files - Run as the group, not the user who started it
find / -perm -g=s -type f 2>/dev/null

#Find Sticky bit files
find / -perm -1000 -type d 2>/dev/null

#Find SUID or SGID (3 folders deep)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/nul
```

