---
description: >-
  A powerful command-line packet analyzer; and libpcap, a portable C/C++ library
  for network traffic capture.
---

# tcpdump

## How to sniff traffic from Android emulator

Check which AVDs are present

```bash
emulator -list-avds
```

Select your AVD and run (**avoid this part if you are running the emulator yet**)

```bash
emulator -avd <non_production_avd_name> -writable-system -no-snapshot
```

Install tcpdump on the Android device (download here: [https://www.androidtcpdump.com/android-tcpdump/downloads](https://www.androidtcpdump.com/android-tcpdump/downloads))

```bash
adb root
adb remount
adb push /wherever/you/put/tcpdump /system/xbin/tcpdump
adb shell chmod 6755 /system/xbin/tcpdump
```

Forward an android port to host

```bash
adb forward tcp:11111 tcp:11111
```

Start sniff traffic with tcpdump

```bash
adb shell
tcpdump -i wlan0 -s0 -w - | nc -l -p 11111
```

Connect wireshark to the forwarded port via netcat

```bash
nc localhost 11111 | wireshark -k -S -i -
```

{% embed url="https://www.tcpdump.org/" %}
