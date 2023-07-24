---
description: >-
  Objection is a runtime mobile exploration toolkit, powered by Frida, built to
  help you assess the security posture of your mobile applications, without
  needing a jailbreak.
---

# objection

## Installation

```
pip3 install objection
```

## Connection

Make a **regular ADB conection** and **start** the **frida** server in the device (and check that frida is working in both the client and the server).

If you are using a **rooted device** it is needed to select the application that you want to test inside the _**--gadget**_ option. in this case:

```
objection --gadget com.sensepost.ipewpew explore
```

## Commands

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

<pre class="language-bash"><code class="lang-bash">file download &#x3C;remote_path> [&#x3C;local path>] (copy file from device)
file upload &#x3C;local_path> [&#x3C;remote path>] (copy file to device)
<strong>
</strong><strong># Imports Fridascript from a file on the local filesystem and executes it as a job. Ex:  import ~/home/hooks/custom.js custom-hook-name
</strong>import &#x3C;local_path> [job_name] [--no-exception-handler]
</code></pre>

### Device actions

```bash
ios plist cat <remote_plist_filename> (parses and echoes a plist file on the remote iOS device to screen)
ios sslpinning disable [--quiet] (attempts to disable SSL Pinning on iOS devices)
ios jailbreak disable (attempts to disable Jailbreak detection on iOS devices)
ios jailbreak simulate (attempts to simulate a Jailbroken iOS environment)
ios monitor crypto monitor (hooks CommonCrypto to output information about cryptographic operation)
ios nsuserdefaults get (queries the applications NSUserDefaults class)
ios pasteboard monitor (hooks into the iOS UIPasteboard class)
ios ui alert <message> (displays an alert popup on an iOS device)
ios ui dump (dumps the current, serialized user interface)
ios ui screenshot (screenshots the current foregrounded UIView and saves it as a PNG locally)
ios ui touchid_bypass
ios cookies get (try to extract cookie values out of the sharedHTTPCookieStorage)
```

### App Analysis

<pre class="language-bash"><code class="lang-bash">ios info binary
ios hooking list classes (lists all of the classes in the current Objective-C runtime)
ios hooking search classes &#x3C;string> (search for classes in the current Objective-C runtime)
ios hooking search methods &#x3C;string> (search for methods in classes in the current Objective-C)
<strong>ios hooking list class_methods &#x3C;class_name> (lists the methods within an Objective-C class)
</strong><strong>ios bundles list_frameworks [--include-apple-frameworks] [--full-path] (returns all of the application's bundles that represent frameworks)
</strong>ios bundles list_bundles [--full-path] (returns all the application's non-framework bundles)
</code></pre>

### Hooking

```bash
# Hooks into a specified Objective-C method and reports on invocations. Ex: ios hooking watch method "+[KeychainDataManager update:forKey:]"
ios hooking watch method "<full class & selector>" [--dump-backtrace] [--dumps-args] [--dump-return] [--include-backtrace]

# Hooks into all of the methods available in the Objective-C class specified. Ex: ios hooking watch KeychainDataManager
ios hooking watch <class_name> [--include-parents]

# Hooks into a specified Objective-C method and sets its return value to either True or False. Ex: ios hooking set return_value "+[JailbreakDetection isJailbroken]" false
ios hooking set return_value "<full class & selector>" <true/false>
```

### Keychain

```bash
ios keychain dump (extracts the keychain items for the current application)
ios keychain add --account <account> --service <service> --data <data> (adds a new entry to the iOS keychain using SecItemAdd)
ios keychain clear (clears all the keychain items for the current application)
```

### Memory

```bash
memory dump all <local path> (dump all memory)
memory dump from_base <base_address> <size_to_tump> <local_path> (dump part of the memory)
memory list modules (list all of the modules loaded in the current process)
memory list exports <module_name> (list exports in a specific loaded module)
memory search "<pattern>" [--string] [--offsets-only] (search the current processes' heap for a pattern)
memory write "<address>" "<pattern>" [--string] (write an arbitrary set of bytes to an address in memory)
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
