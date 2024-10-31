---
description: >-
  Dynamic instrumentation toolkit for developers, reverse-engineers, and
  security researchers.
---

# frida

## Installation

### Client

```bash
pip3 install frida-tools
```

### Server

Download server for architecture from [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases).

```bash
xz -d frida-server-16.5.6-android-arm64.xz
adb root
adb push frida-server-16.5.6-android-arm64 /data/local/tmp
adb shell
cd /data/local/tmp
chmod +x frida-server-16.5.6-android-arm64
./frida-server-16.5.6-android-arm64
```

## Commands

### Connection

```bash
frida -U targetAPK (connect to APK)
frida -U -l script.js targetAPK (execute script and connect to APK)
```

### frida-trace

Trace all calls on `com.testapp.*`:

```bash
frida-trace -U -j 'com.testapp.*!*' TestApp
```

Trace all calls from native library:

```
frida-trace -U -I 'native-lib' -j 'com.testapp.*!*' TestApp
```

## Tracing

### Activies

```javascript
Java.perform(() => {
    let ActivityClass = Java.use("android.app.Activity");
    ActivityClass.onResume.implementation = function() {
        console.log("[*] Activity resumed:", this.getClass().getName());
        this.onResume();
    }
})
```

### Fragments

```javascript
Java.perform(() => {
    let FragmentClass = Java.use("androidx.fragment.app.Fragment");
    FragmentClass.onResume.implementation = function() {
        console.log("[*] Fragment resumed:", this.getClass().getName());
        this.onResume();
    }
})
```

Returning a different output:

```javascript
Java.perform(() => {
    var InterceptionFragment = Java.use("io.hextree.fridatarget.ui.InterceptionFragment");
    InterceptionFragment.function_to_intercept.implementation = function(argument) {
        this.function_to_intercept(argument);
        return "SOMETHING DIFFERENT";
    }
})
```

## JADX and Frida

If we want to load a class from jadx to Frida we can Right Click > Copy as frida snippet. Now paste it into `Java.perform` sentence:

```javascript
Java.perform(() => {
    let ExampleClass = Java.use("io.hextree.fridatarget.ExampleClass");
})
```

Having this class:

```java
package io.hextree.fridatarget;

/* loaded from: classes6.dex */
public class ExampleClass {
    public String returnDecryptedString() {
        return FlagCryptor.decodeFlag("ViBueiBpcmVsIGZycGhlcnlsIHJhcGVsY2dycSE=");
    }

    public String returnDecryptedStringIfPasswordCorrect(String password) {
        if (password.equals("VerySecret")) {
            return FlagCryptor.decodeFlag("WWhweHZ5bCBWIGpuZiBjbmZmamJlcSBjZWJncnBncnEh");
        }
        return null;
    }
}
```

For example we can create an instance of the ExampleClass and console.log the result. Example script:

```javascript
Java.perform(() => {
    let ExampleClass = Java.use("io.hextree.fridatarget.ExampleClass");
    let ExampleInstance = ExampleClass.$new();
    console.log(ExampleInstance.returnDecryptedString());
    console.log(ExampleInstance.returnDecryptedStringIfPasswordCorrect("VerySecret"));
})
```

**It's so much faster than manually reversing!**

{% embed url="https://app.hextree.io/" %}

{% embed url="https://frida.re/docs/android/" %}

{% embed url="https://learnfrida.info/" %}
