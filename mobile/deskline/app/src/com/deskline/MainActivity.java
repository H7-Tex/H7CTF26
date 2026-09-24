package com.deskline;

import android.app.Activity;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import org.json.JSONObject;
import java.util.HashMap;

public class MainActivity extends Activity {
    private Session session;
    private EditText serverField;
    private TextView status;
    private TextView tickets;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        session = new Session(this);
        setContentView(R.layout.activity_main);
        serverField = findViewById(R.id.server);
        status = findViewById(R.id.status);
        tickets = findViewById(R.id.tickets);
        serverField.setText(session.baseUrl());
        findViewById(R.id.sync).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                session.setBaseUrl(serverField.getText().toString().trim());
                sync();
            }
        });
    }

    private void sync() {
        status.setText("Syncing queue...");
        final String base = session.baseUrl();
        new Thread(new Runnable() {
            public void run() {
                String msg;
                try {
                    HashMap<String, String> h = new HashMap<>();
                    h.put("X-Deskline-Client", ApiClient.CLIENT_HEADER);
                    JSONObject body = new JSONObject().put("device_id", session.deviceId());
                    ApiClient.Resp a = ApiClient.post(base + "/api/v1/auth/device", body.toString(), h);
                    if (a.code != 200) {
                        post("Auth failed (" + a.code + ")");
                        return;
                    }
                    session.setToken(new JSONObject(a.body).getString("token"));

                    HashMap<String, String> h2 = new HashMap<>();
                    h2.put("Authorization", "Bearer " + session.token());
                    ApiClient.Resp r = ApiClient.get(base + "/api/v1/sync", h2);
                    if (r.code != 200) {
                        post("Sync failed (" + r.code + ")");
                        return;
                    }
                    new DeskDb(MainActivity.this).seedFromSync(r.body);
                    msg = "Queue synced";
                } catch (Exception e) {
                    msg = "Error: " + e.getMessage();
                }
                post(msg);
                renderTickets();
            }
        }).start();
    }

    private void renderTickets() {
        final StringBuilder sb = new StringBuilder();
        try {
            SQLiteDatabase db = new DeskDb(this).getReadableDatabase();
            Cursor c = db.rawQuery("SELECT subject, body FROM tickets", null);
            while (c.moveToNext()) {
                sb.append("• ").append(c.getString(0)).append("\n    ")
                  .append(c.getString(1)).append("\n\n");
            }
            c.close();
            db.close();
        } catch (Exception ignored) {
        }
        runOnUiThread(new Runnable() {
            public void run() {
                tickets.setText(sb.toString());
            }
        });
    }

    private void post(final String msg) {
        runOnUiThread(new Runnable() {
            public void run() {
                status.setText(msg);
            }
        });
    }
}
