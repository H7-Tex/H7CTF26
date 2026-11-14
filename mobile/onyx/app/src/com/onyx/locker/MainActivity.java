package com.onyx.locker;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.util.HashMap;

public class MainActivity extends Activity {
    private Session session;
    private EditText serverField;
    private TextView status;
    private TextView vault;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        session = new Session(this);
        setContentView(R.layout.activity_main);
        serverField = findViewById(R.id.server);
        status = findViewById(R.id.status);
        vault = findViewById(R.id.vault);
        serverField.setText(session.baseUrl());
        findViewById(R.id.sync).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                session.setBaseUrl(serverField.getText().toString().trim());
                sync();
            }
        });
    }

    private void sync() {
        status.setText("Syncing vault...");
        final String base = session.baseUrl();
        new Thread(new Runnable() {
            public void run() {
                String msg, display = "";
                try {
                    HashMap<String, String> h = new HashMap<>();
                    h.put("X-Onyx-Client", ApiClient.CLIENT_HEADER);
                    JSONObject body = new JSONObject().put("device_id", session.deviceId());
                    ApiClient.Resp a = ApiClient.post(base + "/api/v1/auth/device", body.toString(), h);
                    if (a.code != 200) {
                        post("Auth failed (" + a.code + ")", "");
                        return;
                    }
                    String token = new JSONObject(a.body).getString("token");
                    session.setToken(token);

                    HashMap<String, String> h2 = new HashMap<>();
                    h2.put("Authorization", "Bearer " + token);
                    ApiClient.Resp r = ApiClient.get(base + "/api/v1/vault/sync", h2);
                    if (r.code != 200) {
                        post("Sync failed (" + r.code + ")", "");
                        return;
                    }

                    // cache the vault locally for offline access
                    cacheVault(r.body);

                    JSONArray items = new JSONObject(r.body).getJSONArray("items");
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < items.length(); i++) {
                        JSONObject it = items.getJSONObject(i);
                        sb.append(it.getString("label")).append("\n    ")
                          .append(it.optString("username")).append("  ")
                          .append(mask(it.getString("secret"))).append("\n\n");
                    }
                    display = sb.toString();
                    msg = "Synced " + items.length() + " items (cached offline)";
                } catch (Exception e) {
                    msg = "Error: " + e.getMessage();
                }
                post(msg, display);
            }
        }).start();
    }

    private void cacheVault(String json) throws Exception {
        byte[] enc = VaultCrypto.encrypt(json.getBytes("UTF-8"));
        FileOutputStream fos = new FileOutputStream(new File(getFilesDir(), "vault.enc"));
        fos.write(enc);
        fos.close();
    }

    private static String mask(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) b.append('•');
        return b.toString();
    }

    private void post(final String msg, final String display) {
        runOnUiThread(new Runnable() {
            public void run() {
                status.setText(msg);
                vault.setText(display);
            }
        });
    }
}
