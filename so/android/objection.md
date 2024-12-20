---
description: >-
  Objection is a runtime mobile exploration toolkit, powered by Frida, built to
  help you assess the security posture of your mobile applications, without
  needing a jailbreak.
---

# objection

## Installation

```bash
pip3 install objection
```

## Connection

Make a **regular ADB conection** and **start** the **frida** server in the device (and check that frida is working in both the client and the server).

If you are using a **rooted device** it is needed to select the application that you want to test inside the _**--gadget**_ option. in this case:

```bash
objection --gadget com.sensepost.ipewpew explore
```

## Commands

### Patch apk

Before you can use any of the objection commands on an Android application, the application's APK itself needs to be patched and code signed to load the frida-gadget.so on start (**or setup frida-server**).

{% code overflow="wrap" %}
```bash
objection patchapk -s testAPK.apk
```
{% endcode %}

### Objection Basics

```bash
! (executes operating system commands using pythons subprocess module)
env (enumerate interesting directories that relate to the application)
reconnect (attempts to reconnect to the Frida Gadget specified with --gadget on startup)
frida (print frida information)
jobs list (list the currently running jobs)
jobs kill <job_uuid> (kills a running job identified by its UUID)
plugin load <local_path> (loads an objection plugin into the current session)
```

### File Operations

```bash
file download <remote_path> [<local path>] (copy file from device)
file upload <local_path> [<remote path>] (copy file to device)

# Imports Fridascript from a file on the local filesystem and executes it as a job. Ex:  import ~/home/hooks/custom.js custom-hook-name
import <local_path> [job_name] [--no-exception-handler]
```

### Device actions

```bash
android sslpinning disable [--quiet] (attempts to disable SSL Pinning on Android devices)
android root disable (attempts to disable root detection on Android devices)
android root simulate (attempts to simulate a rooted Android environment)
android shell_exec whoami (executes command)
android ui screenshot /tmp/screenshot (make a screenshot)
android clipboard monitor (gets a handle on the Android clipboard service)
```

### App Analysis

```bash
android hooking list activities (list activities of the app)
android hooking list services (list services of the app)
android hooking list receivers (list receivers of the app)
android hooking list classes (list all classes)
android hooking get current_activity (get current activity)
android hooking search classes <string> (search classes)
android hooking search methods <string> (search methods)
android hooking list class_methods <class_name> (list declared methods of a class with their parameters)
android ui FLAG_SECURE <true/false> (control the value of FLAG_SECURE for the current Activity)
```

### Hooking

```bash
# Hooks a specified class method and reports on invocations. Ex: android hooking watch class_method com.example.test.login
android hooking watch class_method <fully qualified class method> [--dump-args] [--dump-backtrace] [--dump-return]

# Hooks a specified class' methods and reports on invocations. Ex: android hooking watch class com.example.test
android hooking watch class <class>

# Sets a methods return value to always be true / false. Ex: android hooking set return_value com.example.test.rootUtils.isRooted false
android hooking set return_value "<fully qualified class>" "<overload if needed>" <true / false>
```

### Keystore

```bash
android keystore list (lists aliases in the current applications 'AndroidKeyStore' KeyStore)
android keystore detail (lists detailed 'AndroidKeyStore' items for the current application)
android keystore clear (clears all aliases in the current applications 'AndroidKeyStore' Keystore)
```

### Intents

```bash
android intents launch_activity <activity> (launches an activity class by building a new Intent)
android intent launch_service <service_class> (launches an exported service class by building a new Intent)
```

### Memory

```bash
memory dump all <local path> (dump all memory)
memory dump from_base <base_address> <size_to_tump> <local_path> (dump part of the memory)
memory list modules (list all of the modules loaded in the current process)
memory list exports <module_name> (list exports in a specific loaded module)
memory search "<pattern>" [--string] [--offsets-only] (search the current processes' heap for a pattern)
memory write "<address>" "<pattern>" [--string] (write an arbitrary set of bytes to an address in memory)
android heap search instances <class> (search for and print live instances of a specific Java class)
```

### SQLite

```bash
sqlite connect <remote_path> (connect to a SQLite database on the remote device)
sqlite disconnect (disconnect from the currently connected SQLite database file)
sqlite status (check the status of the SQLite connection)
sqlite sync (sync the locally cached SQLite database with the remote database)
sqlite execute schema (get the database schema for the currently connected SQLite database)
sqlite execute query <sql_query> (execute a query against the cached copy of the connected SQLite database)
```

## References

{% embed url="https://github.com/sensepost/objection" %}
