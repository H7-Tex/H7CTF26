package com.meridian.pay;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

public class RouterActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Uri data = getIntent().getData();
        String target = null;
        if (data != null) target = data.getQueryParameter("url");
        if (target == null || target.isEmpty()) {
            Session s = new Session(this);
            target = s.baseUrl() + "/api/v1/promo/public";
        }
        Intent i = new Intent(this, WebViewActivity.class);
        i.putExtra("url", target);
        startActivity(i);
        finish();
    }
}
