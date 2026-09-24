package com.meridian.pay;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.util.HashMap;

public class WebViewActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        WebView web = new WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.setWebViewClient(new WebViewClient());
        setContentView(web);

        String url = getIntent().getStringExtra("url");
        if (url == null) {
            finish();
            return;
        }

        Session s = new Session(this);
        HashMap<String, String> headers = new HashMap<>();
        String origin = s.baseUrl();
        if (url.startsWith(origin)) {
            String token = s.token();
            if (token != null) headers.put("Authorization", "Bearer " + token);
            headers.put("X-Meridian-Client", ApiClient.CLIENT_HEADER);
        }
        web.loadUrl(url, headers);
    }
}
