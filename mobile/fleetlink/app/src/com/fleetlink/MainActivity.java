package com.fleetlink;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.HashMap;
import java.util.TreeMap;

public class MainActivity extends Activity {
    private Session session;
    private EditText serverField;
    private TextView status;
    private TextView trips;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        session = new Session(this);
        setContentView(R.layout.activity_main);
        serverField = findViewById(R.id.server);
        status = findViewById(R.id.status);
        trips = findViewById(R.id.trips);
        serverField.setText(session.baseUrl());
        findViewById(R.id.load).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                session.setBaseUrl(serverField.getText().toString().trim());
                load();
            }
        });
    }

    private void load() {
        status.setText("Loading trips...");
        final String base = session.baseUrl();
        new Thread(new Runnable() {
            public void run() {
                String msg, display = "";
                try {
                    String path = "/api/v1/trips";
                    TreeMap<String, String> params = new TreeMap<>();
                    params.put("scope", "mine");
                    Signer.Signed s = Signer.sign("GET", path, params, session.deviceId());

                    HashMap<String, String> h = new HashMap<>();
                    h.put("X-Device-Id", s.deviceId);
                    h.put("X-Ts", s.ts);
                    h.put("X-Sig", s.sig);
                    ApiClient.Resp r = ApiClient.get(base + path + "?" + s.query, h);
                    if (r.code != 200) {
                        post("Request failed (" + r.code + ")", "");
                        return;
                    }
                    JSONArray t = new JSONObject(r.body).getJSONArray("trips");
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < t.length(); i++) {
                        JSONObject it = t.getJSONObject(i);
                        sb.append(it.getString("id")).append("  ")
                          .append(it.getString("from")).append(" -> ").append(it.getString("to"))
                          .append("\n    ").append(it.getString("status")).append("\n\n");
                    }
                    display = sb.toString();
                    msg = "Loaded " + t.length() + " trips";
                } catch (Exception e) {
                    msg = "Error: " + e.getMessage();
                }
                post(msg, display);
            }
        }).start();
    }

    private void post(final String msg, final String display) {
        runOnUiThread(new Runnable() {
            public void run() {
                status.setText(msg);
                trips.setText(display);
            }
        });
    }
}
