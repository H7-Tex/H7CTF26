package com.meridian.pay;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import org.json.JSONObject;
import java.io.File;
import java.io.FileWriter;

public class MainActivity extends Activity {
    private Session session;
    private EditText serverField;
    private TextView status;
    private TextView account;
    private Button promo;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        session = new Session(this);
        seedReceipts();

        setContentView(R.layout.activity_main);
        serverField = findViewById(R.id.server);
        status = findViewById(R.id.status);
        account = findViewById(R.id.account);
        promo = findViewById(R.id.promo);
        serverField.setText(session.baseUrl());

        findViewById(R.id.connect).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                session.setBaseUrl(serverField.getText().toString().trim());
                connect();
            }
        });
        promo.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Intent i = new Intent(MainActivity.this, WebViewActivity.class);
                i.putExtra("url", session.baseUrl() + "/api/v1/promo/public");
                startActivity(i);
            }
        });
        findViewById(R.id.share).setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                Uri u = Uri.parse("content://com.meridian.pay.export/files/receipt-8827.txt");
                Intent s = new Intent(Intent.ACTION_SEND);
                s.setType("text/plain");
                s.putExtra(Intent.EXTRA_STREAM, u);
                s.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                startActivity(Intent.createChooser(s, "Share receipt"));
            }
        });
        promo.setEnabled(session.token() != null);
        if (session.token() != null) account.setText("Signed in as " + session.accountName());
    }

    private void connect() {
        status.setText("Authenticating device...");
        promo.setEnabled(false);
        final String base = session.baseUrl();
        new Thread(new Runnable() {
            public void run() {
                String msg, name = null, token = null;
                try {
                    JSONObject body = new JSONObject().put("device_id", session.deviceId());
                    java.util.HashMap<String, String> h = new java.util.HashMap<>();
                    h.put("X-Meridian-Client", ApiClient.CLIENT_HEADER);
                    ApiClient.Resp r = ApiClient.post(base + "/api/v1/auth/device", body.toString(), h);
                    if (r.code == 200) {
                        JSONObject j = new JSONObject(r.body);
                        token = j.getString("token");
                        name = j.getString("name");
                        msg = "Connected";
                    } else {
                        msg = "Auth failed (" + r.code + ")";
                    }
                } catch (Exception e) {
                    msg = "Connection error: " + e.getMessage();
                }
                final String fmsg = msg, fname = name, ftoken = token;
                runOnUiThread(new Runnable() {
                    public void run() {
                        if (ftoken != null) {
                            session.setSession(ftoken, fname);
                            account.setText("Signed in as " + fname);
                            promo.setEnabled(true);
                        }
                        status.setText(fmsg);
                    }
                });
            }
        }).start();
    }

    private void seedReceipts() {
        try {
            File dir = new File(getFilesDir(), "receipts");
            dir.mkdirs();
            File f = new File(dir, "receipt-8827.txt");
            if (!f.exists()) {
                FileWriter w = new FileWriter(f);
                w.write("Meridian Pay receipt\nAccount MP-0041-8827\nAmount: $18.42\nStatus: settled\n");
                w.close();
            }
        } catch (Exception ignored) {
        }
    }
}
