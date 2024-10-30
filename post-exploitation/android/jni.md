# jni

## JNI Deobfuscation

### Reversing the library

Ghidra / IDA Pro / radare2 and GL my friend!

### Executing the functions from JNI in an Android app

Create a New Project on Android Studio

```bash
# Android Studio > New > New Project > Empty Views Activity
```

Copy all folders from `resources/lib/*` from the original to `app/jniLibs/*` in new project

Create a new Java class in AS "java" folder (including class name)

<pre class="language-bash"><code class="lang-bash"><strong># App: io.hextree.weatherusa
</strong># Class name: InternetUtil
io.hextree.weatherusa.InternetUtil
</code></pre>

Check the logic of using the native library (this is the decompiler code)

{% code overflow="wrap" %}
```java
package io.hextree.weatherusa;

[...]

public abstract class InternetUtil {
[...]
    httpURLConnection2.setRequestProperty("X-API-KEY", getKey("jhnef6d~efu?tjfus3tobunaa3tbdrun"));
[...]

    private static native String getKey(String str);
}
```
{% endcode %}

And make it usable on our class (`java/io.hextree.weatherusa/InternetUtil.java`)

{% code overflow="wrap" %}
```java
package io.hextree.weatherusa;

public class InternetUtil {
    private static native String getKey(String str);

    public static String solve(){
        System.loadLibrary("native-lib");
        return getKey("jhnef6d~efu?tjfus3tobunaa3tbdrun");
    }
}
```
{% endcode %}

Finally, call to our new class from MainActivity (`java/com.example.empty_for_pocs_java/MainActivity.java`)

{% code overflow="wrap" %}
```java
package com.example.empty_for_pocs_java;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import io.hextree.weatherusa.InternetUtil;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView homeText = findViewById(R.id.home_text);
        homeText.setText(String.format("API: %s", InternetUtil.solve()));
    }
}
```
{% endcode %}

Set the homeText "id" in activity\_main (`res/layout/activity_main.xml`)

{% code overflow="wrap" %}
```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:id="@+id/main"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">

    <TextView
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Hello World!"
        android:id="@+id/home_text"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        tools:visibility="visible" />

</androidx.constraintlayout.widget.ConstraintLayout>
```
{% endcode %}

{% embed url="https://developer.android.com/training/articles/perf-jni?hl=es-419" %}
