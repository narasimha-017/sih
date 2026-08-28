package com.example.emailthreat;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MainActivity extends Activity {
  @Override public void onCreate(Bundle state) {
    super.onCreate(state);
    WebView w = new WebView(this);
    w.setWebViewClient(new WebViewClient());
    w.getSettings().setJavaScriptEnabled(true);
    w.getSettings().setDomStorageEnabled(true);
    w.loadUrl("https://YOUR-MAILSENTINEL-DOMAIN.example/");
    setContentView(w);
  }
}
