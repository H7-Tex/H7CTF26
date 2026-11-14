package com.onyx.locker;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.UUID;

public class Session {
    private final SharedPreferences sp;

    public Session(Context ctx) {
        sp = ctx.getSharedPreferences("onyx", Context.MODE_PRIVATE);
    }

    public String deviceId() {
        String d = sp.getString("device_id", null);
        if (d == null) {
            d = "onx-" + UUID.randomUUID().toString();
            sp.edit().putString("device_id", d).apply();
        }
        return d;
    }

    public String baseUrl() {
        return sp.getString("base_url", "http://10.0.2.2:8080");
    }

    public void setBaseUrl(String u) {
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        sp.edit().putString("base_url", u).apply();
    }

    public String token() {
        return sp.getString("token", null);
    }

    public void setToken(String t) {
        sp.edit().putString("token", t).apply();
    }
}
