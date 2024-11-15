---
description: >-
  Tool for reverse engineering 3rd party, closed, binary Android apps. It can
  decode resources to nearly original form and rebuild them after making some
  modifications.
---

# apktool

## Commands

### Decode

```bash
# Decode apk/file to a folder
apktool d package.apk -o package

# Options:
-b: do not write debug info
-f: force delete destination folder
-k: use if there was an error and some resources were dropped
-m: keep files to closest to original as possible (prevent rebuilds)
-o: output folder (default: apk.out)
-p: use framework files located in <folder>
-r: do not decode resources
-s: do not decode sources
-t: use framework files tagged by <tag>
```

### Build

```bash
# Build an apk/jar file from folder
apktool b package -o package.apk

# Options:
-a: load aapt from specified location
-api: numeric api-level of the file to generate
-c: copy original AndroidManifest.xml and META-INF
-d: set android:debuggable to "true" in the APK's compiled manifest
-f: skip changes detection and build all files
-n: add generic network security configuration file in the output apk
-nc: disable crunching of resource files during the build step
-o: that name of apk that gets written (default: dist/name.apk)
-p: use framework files located in <folder>
```

## How to rebuild a modified apk

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># Decompile apk
apktool d package.apk

<strong># Modify the files that you want!!
</strong>
# Rebuild apk (from the folder of apk extracted)
apktool b

# Generate the key to sign
keytool -genkey -v -keystore research.keystore -alias research_key -keyalg RSA -keysize 2048 -validity 10000

# Sign the apk with the key
<strong>    # Option 1: jarsigner (v1 scheme)
</strong>    jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore research.keystore dist/apk_build.apk research_key

    # Option 2: apksigner (v2, v3, v4 scheme) - RECOMMENDED
    apksigner sign --ks research.keystore --ks-key-alias research_key dist/apk_build.apk

# Optional: Zipalign to optimize APK (may cause problems with modern schemes)
/path/to/Android/sdk/build-tools/VERSION/zipalign -v -p 4 input.apk output.apk
</code></pre>

## Patching Network Security Config

Unpack the target apk and modify the AndroidManifest.xml to add networkSecurityConfig

```bash
<application android:networkSecurityConfig="@xml/network_security_config" [...]
```

Create a permissive file on `res/xml/network_security_config.xml`

```xml
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="user"/>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

Rebuild the apk as explained in [#how-to-rebuild-a-modified-apk](apktool.md#how-to-rebuild-a-modified-apk "mention").

## References

{% embed url="https://github.com/iBotPeaches/Apktool" %}
