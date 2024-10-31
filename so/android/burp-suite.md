---
description: >-
  The class-leading vulnerability scanning, penetration testing, and web app
  security platform.
---

# burp suite

## Configuring burp suite to work as Android proxy

### Configure a dedicated proxy listener in Burp

1. In Burp, open the Settings dialog.
2. Go to Tools > Proxy.
3. Under Proxy Listeners, click Add.
4. On the Binding tab, set Bind to port to any available port.
5. Set Bind to address to All interfaces.
6. Click OK and confirm your entries when prompted.

#### **Optional:** Transparent Proxy (for DNS spoofing)

1. Proxy listener Bind to port 80.
2. Request Handling > Check Support invisible proxying.
3. Same process for port 443.

### Configure Android to proxy traffic through Burp

1. On your Android device, go to the network and internet settings.
2. Open the network details for the Wi-Fi network that you want to use for testing.
3. Enter edit mode.
4. In the advanced settings, choose the option to configure a proxy manually.
5. Set the Proxy hostname to the IP address of the machine you're using to run Burp.
6. Set the Proxy port to the port you assigned to the new proxy listener you configured in Burp. For more information, see Configure a dedicated proxy listener in Burp
7. Save your changes and then connect to the Wi-Fi network. Your device's web traffic is now proxied through Burp.

### Add Burp's CA certificate to your device's trust store (user way)

1. In Burp, open the Settings dialog.
2. Go to Tools > Proxy.
3. Under Proxy Listeners, click Import / export CA certificate.
4. In CA Certificate dialog, select Export > Certificate in DER format and click Next.
5. Enter a filename and location for the certificate. Note that you need to explicitly include the .der file extension.
6. Click Next. The dialog indicates that the certificate was successfully exported.
7. Add the certificate to your device's trust store. The process for doing this varies depending on the device or emulator you're using, as well your Android OS version. You can find detailed, third-party instructions on how to do this online.

### Install Burp's CA certificate as system

1. Install the proxy certificate as a regular user certificate.
2. Ensure you are root (`adb root`), and execute the following commands in `adb shell`

```bash
# Backup the existing system certificates to the user certs folder
cp /system/etc/security/cacerts/* /data/misc/user/0/cacerts-added/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# copy all system certs and our user cert into the tmpfs system certs folder
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Fix any permissions & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
```

### Install System Certs on Android 14

This method also requires root access. First install your proxy certificate as a regular user cert. Then run the following script created by Tim Perry from [HTTP Toolkit](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/) (credits [https://app.hextree.io/](https://app.hextree.io/)):

```bash
# Create a separate temp directory, to hold the current certificates
# Otherwise, when we add the mount we can't read the current certs anymore.
mkdir -p -m 700 /data/local/tmp/tmp-ca-copy

# Copy out the existing certificates
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/tmp-ca-copy/

# Create the in-memory mount on top of the system certs folder
mount -t tmpfs tmpfs /system/etc/security/cacerts

# Copy the existing certs back into the tmpfs, so we keep trusting them
mv /data/local/tmp/tmp-ca-copy/* /system/etc/security/cacerts/

# Copy our new cert in, so we trust that too
cp /data/misc/user/0/cacerts-added/* /system/etc/security/cacerts/

# Update the perms & selinux context labels
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*

# Deal with the APEX overrides, which need injecting into each namespace:

# First we get the Zygote process(es), which launch each app
ZYGOTE_PID=$(pidof zygote || true)
ZYGOTE64_PID=$(pidof zygote64 || true)
# N.b. some devices appear to have both!

# Apps inherit the Zygote's mounts at startup, so we inject here to ensure
# all newly started apps will see these certs straight away:
for Z_PID in "$ZYGOTE_PID" "$ZYGOTE64_PID"; do
    if [ -n "$Z_PID" ]; then
        nsenter --mount=/proc/$Z_PID/ns/mnt -- \
            /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
    fi
done

# Then we inject the mount into all already running apps, so they
# too see these CA certs immediately:

# Get the PID of every process whose parent is one of the Zygotes:
APP_PIDS=$(
    echo "$ZYGOTE_PID $ZYGOTE64_PID" | \
    xargs -n1 ps -o 'PID' -P | \
    grep -v PID
)

# Inject into the mount namespace of each of those apps:
for PID in $APP_PIDS; do
    nsenter --mount=/proc/$PID/ns/mnt -- \
        /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts &
done
wait # Launched in parallel - wait for completion here

echo "System certificate injected"
```

{% embed url="https://portswigger.net/burp" %}
