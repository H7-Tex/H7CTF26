package com.deskline;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

public class ApiClient {
    public static final String CLIENT_HEADER = "Deskline-Android/1.6.0";

    public static class Resp {
        public int code;
        public String body;
    }

    public static Resp post(String url, String json, Map<String, String> headers) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        c.setRequestProperty("Content-Type", "application/json");
        if (headers != null) for (Map.Entry<String, String> e : headers.entrySet())
            c.setRequestProperty(e.getKey(), e.getValue());
        c.setDoOutput(true);
        try (OutputStream os = c.getOutputStream()) {
            os.write(json.getBytes("UTF-8"));
        }
        return read(c);
    }

    public static Resp get(String url, Map<String, String> headers) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("GET");
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        if (headers != null) for (Map.Entry<String, String> e : headers.entrySet())
            c.setRequestProperty(e.getKey(), e.getValue());
        return read(c);
    }

    private static Resp read(HttpURLConnection c) throws Exception {
        Resp r = new Resp();
        r.code = c.getResponseCode();
        InputStream in = r.code >= 400 ? c.getErrorStream() : c.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        if (in != null) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        }
        r.body = bos.toString("UTF-8");
        c.disconnect();
        return r;
    }
}
